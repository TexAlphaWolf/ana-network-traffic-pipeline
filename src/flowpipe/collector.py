"""UDP collector for NetFlow v5/v9 and IPFIX."""

from __future__ import annotations

import ipaddress
import logging
import socket
import time
from threading import Event

from .anonymise import Anonymiser
from .ingest import anonymise_flow
from .model import Flow
from .netflow import FlowParseError, TemplateCache, parse_datagram
from .store import Store, StoreError

LOG = logging.getLogger("flowpipe.collector")
MAX_DATAGRAM = 65_535
MAX_PENDING = 200_000  # flows kept in memory while ClickHouse is unreachable


class Collector:
    def __init__(
        self,
        store: Store,
        allowed: tuple[str, ...] = (),
        batch_size: int = 5000,
        flush_seconds: float = 5.0,
        anonymiser: Anonymiser | None = None,
    ) -> None:
        self.store = store
        self.allowed = tuple(ipaddress.ip_network(item) for item in allowed)
        self.batch_size = batch_size
        self.flush_seconds = flush_seconds
        self.anonymiser = anonymiser
        self.templates = TemplateCache()
        self.pending: list[Flow] = []
        self.received = self.rejected = self.malformed = self.stored = self.dropped = 0
        self._last_flush = time.monotonic()

    def permitted(self, address: str) -> bool:
        if not self.allowed:
            return True
        try:
            ip = ipaddress.ip_address(address.split("%")[0])
        except ValueError:
            return False
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        return any(ip in net for net in self.allowed if net.version == ip.version)

    def handle(self, data: bytes, address: str) -> int:
        """Process one datagram from `address`. Returns how many flows it contained."""
        if not self.permitted(address):
            self.rejected += 1
            return 0
        self.received += 1
        try:
            flows = parse_datagram(data, address, self.templates)
        except FlowParseError as error:
            self.malformed += 1
            LOG.debug("malformed datagram from %s: %s", address, error)
            return 0
        if self.anonymiser is not None:
            flows = [anonymise_flow(flow, self.anonymiser) for flow in flows]
        self.pending.extend(flows)
        if len(self.pending) > MAX_PENDING:
            overflow = len(self.pending) - MAX_PENDING
            del self.pending[:overflow]
            self.dropped += overflow
        return len(flows)

    def flush(self, force: bool = False) -> int:
        due = time.monotonic() - self._last_flush >= self.flush_seconds
        if not self.pending or not (force or due or len(self.pending) >= self.batch_size):
            return 0
        batch = self.pending[: self.batch_size * 4]
        try:
            stored = self.store.insert_flows(batch)
        except StoreError as error:
            self._last_flush = time.monotonic()
            if not error.retryable:
                # The server rejected the data itself: retrying would block everything behind it.
                LOG.error("dropping %d flows the database rejected: %s", len(batch), error)
                del self.pending[: len(batch)]
                self.dropped += len(batch)
            else:
                LOG.warning("cannot store flows, will retry: %s", error)
            return 0
        del self.pending[: len(batch)]
        self.stored += stored
        self._last_flush = time.monotonic()
        return stored

    def serve(self, host: str, port: int, stop: Event, ready: Event | None = None) -> None:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.bind((host, port))
            sock.settimeout(1.0)
            LOG.info("collecting NetFlow/IPFIX on %s:%d", host, sock.getsockname()[1])
            if ready is not None:
                self.bound_port = sock.getsockname()[1]
                ready.set()
            while not stop.is_set():
                try:
                    data, peer = sock.recvfrom(MAX_DATAGRAM)
                except TimeoutError:
                    self.flush()
                    continue
                try:
                    self.handle(data, peer[0])
                    self.flush()
                except Exception:  # a daemon must survive one bad datagram
                    LOG.exception("unexpected error while handling a datagram from %s", peer[0])
                    self.malformed += 1
        while self.pending and self.flush(force=True):
            pass

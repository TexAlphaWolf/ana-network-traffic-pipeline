"""NetFlow v5, v9 and IPFIX decoding.

Datagrams come from the network, so they are untrusted: every offset and length is
checked, template counts are bounded, and malformed datagrams raise `FlowParseError`
instead of crashing the collector.
"""

from __future__ import annotations

import ipaddress
import struct
from collections import OrderedDict
from collections.abc import Iterator
from dataclasses import dataclass

from .model import MAX_COUNTER, Flow

MAX_TEMPLATES = 4096
MAX_FIELDS = 256
MAX_RECORDS = 4096

# Information elements shared by NetFlow v9 field types and IPFIX (RFC 5102 / RFC 3954).
IN_BYTES, IN_PKTS, PROTOCOL, TCP_FLAGS = 1, 2, 4, 6
L4_SRC_PORT, IPV4_SRC, L4_DST_PORT, IPV4_DST = 7, 8, 11, 12
LAST_SWITCHED, FIRST_SWITCHED = 21, 22
IPV6_SRC, IPV6_DST = 27, 28
OCTET_TOTAL, PACKET_TOTAL = 85, 86
FLOW_START_SEC, FLOW_END_SEC = 150, 151
FLOW_START_MS, FLOW_END_MS = 152, 153
SAMPLING_INTERVAL = 34


class FlowParseError(ValueError):
    """The datagram is not valid NetFlow/IPFIX."""


@dataclass(frozen=True, slots=True)
class Template:
    fields: tuple[tuple[int, int], ...]  # (element id, length; 0xFFFF = variable)
    size: int  # fixed record size, 0 if any field is variable


class TemplateCache:
    """Templates learned from each exporter, bounded in size (least recently used goes first)."""

    def __init__(self, limit: int = MAX_TEMPLATES) -> None:
        self._items: OrderedDict[tuple[str, int, int], Template] = OrderedDict()
        self._limit = limit

    def __len__(self) -> int:
        return len(self._items)

    def put(self, exporter: str, domain: int, template_id: int, template: Template) -> None:
        key = (exporter, domain, template_id)
        self._items[key] = template
        self._items.move_to_end(key)
        while len(self._items) > self._limit:
            self._items.popitem(last=False)

    def get(self, exporter: str, domain: int, template_id: int) -> Template | None:
        key = (exporter, domain, template_id)
        found = self._items.get(key)
        if found is not None:
            self._items.move_to_end(key)
        return found

    def drop_exporter(self, exporter: str, domain: int) -> None:
        for key in [k for k in self._items if k[0] == exporter and k[1] == domain]:
            del self._items[key]


def _address(raw: bytes) -> str:
    return str(ipaddress.ip_address(raw))


def _uint(raw: bytes) -> int:
    return int.from_bytes(raw, "big")


def parse_v5(data: bytes, exporter: str) -> list[Flow]:
    if len(data) < 24:
        raise FlowParseError("short v5 header")
    _, count, uptime, secs, nsecs, _seq, _et, _eid, sampling = struct.unpack_from(
        "!HHIIIIBBH", data, 0
    )
    if count > 30 or len(data) < 24 + count * 48:
        raise FlowParseError("v5 record count does not match the datagram size")
    interval = max(1, sampling & 0x3FFF)
    export_ms = secs * 1000 + nsecs // 1_000_000
    flows = []
    for index in range(count):
        offset = 24 + index * 48
        (src, dst, _nh, _in, _out, packets, octets, first, last, sport, dport, _p, flags, proto) = (
            struct.unpack_from("!4s4s4sHHIIIIHHBBB", data, offset)
        )
        flows.append(
            Flow(
                start_ms=export_ms - ((uptime - first) & 0xFFFFFFFF),
                end_ms=export_ms - ((uptime - last) & 0xFFFFFFFF),
                src=_address(src),
                dst=_address(dst),
                sport=sport,
                dport=dport,
                proto=proto,
                bytes=min(octets * interval, MAX_COUNTER),
                packets=min(packets * interval, MAX_COUNTER),
                tcp_flags=flags,
                source="netflow",
                exporter=exporter,
            )
        )
    return flows


def _template_fields(data: bytes, offset: int, count: int, ipfix: bool) -> tuple[tuple, int]:
    if count > MAX_FIELDS:
        raise FlowParseError("template with too many fields")
    fields = []
    for _ in range(count):
        if offset + 4 > len(data):
            raise FlowParseError("truncated template")
        element, length = struct.unpack_from("!HH", data, offset)
        offset += 4
        if ipfix and element & 0x8000:  # enterprise-specific element: skip its 4-byte id
            if offset + 4 > len(data):
                raise FlowParseError("truncated template")
            offset += 4
            element = 0  # unknown to us, but its length still matters
        fields.append((element, length))
    return tuple(fields), offset


def _make_template(fields: tuple) -> Template:
    size = 0 if any(length == 0xFFFF for _, length in fields) else sum(n for _, n in fields)
    return Template(fields, size)


def _read_templates(
    body: bytes, exporter: str, domain: int, cache: TemplateCache, ipfix: bool
) -> None:
    offset = 0
    while offset + 4 <= len(body):
        template_id, count = struct.unpack_from("!HH", body, offset)
        offset += 4
        if template_id < 256 and count == 0 and ipfix:
            cache.drop_exporter(exporter, domain)  # template withdrawal
            continue
        if template_id < 256:
            raise FlowParseError("template id below 256")
        fields, offset = _template_fields(body, offset, count, ipfix)
        cache.put(exporter, domain, template_id, _make_template(fields))


def _variable(body: bytes, offset: int) -> tuple[bytes, int]:
    if offset >= len(body):
        raise FlowParseError("truncated variable-length field")
    length = body[offset]
    offset += 1
    if length == 255:
        if offset + 2 > len(body):
            raise FlowParseError("truncated variable-length field")
        length = struct.unpack_from("!H", body, offset)[0]
        offset += 2
    if offset + length > len(body):
        raise FlowParseError("variable-length field overruns the set")
    return body[offset : offset + length], offset + length


def _decode_records(
    body: bytes,
    template: Template,
    exporter: str,
    base_ms: int,
    uptime_ms: int | None,
    ipfix: bool,
) -> list[Flow]:
    flows: list[Flow] = []
    offset = 0
    minimum = template.size or 1
    while offset + minimum <= len(body) and len(flows) < MAX_RECORDS:
        values: dict[int, bytes] = {}
        for element, length in template.fields:
            if length == 0xFFFF:
                value, offset = _variable(body, offset)
            else:
                if offset + length > len(body):
                    return flows  # padding at the end of the set
                value = body[offset : offset + length]
                offset += length
            if element and element not in values:
                values[element] = value
        flow = _build_flow(values, exporter, base_ms, uptime_ms, ipfix)
        if flow is not None:
            flows.append(flow)
    return flows


def _build_flow(
    v: dict[int, bytes], exporter: str, base_ms: int, uptime_ms: int | None, ipfix: bool
) -> Flow | None:
    if IPV4_SRC in v and IPV4_DST in v:
        src, dst = v[IPV4_SRC], v[IPV4_DST]
    elif IPV6_SRC in v and IPV6_DST in v:
        src, dst = v[IPV6_SRC], v[IPV6_DST]
    else:
        return None  # an options record or a layer-2 flow: nothing to analyse
    if len(src) not in (4, 16) or len(dst) not in (4, 16):
        return None
    size = v.get(IN_BYTES) or v.get(OCTET_TOTAL)
    count = v.get(IN_PKTS) or v.get(PACKET_TOTAL)
    if size is None or count is None:
        return None
    if FLOW_START_MS in v:
        start, end = _uint(v[FLOW_START_MS]), _uint(v.get(FLOW_END_MS, v[FLOW_START_MS]))
    elif FLOW_START_SEC in v:
        start = _uint(v[FLOW_START_SEC]) * 1000
        end = _uint(v.get(FLOW_END_SEC, v[FLOW_START_SEC])) * 1000
    elif FIRST_SWITCHED in v and uptime_ms is not None:
        start = base_ms - ((uptime_ms - _uint(v[FIRST_SWITCHED])) & 0xFFFFFFFF)
        end = base_ms - ((uptime_ms - _uint(v.get(LAST_SWITCHED, v[FIRST_SWITCHED]))) & 0xFFFFFFFF)
    else:
        start = end = base_ms
    interval = max(1, _uint(v[SAMPLING_INTERVAL])) if SAMPLING_INTERVAL in v else 1
    try:
        return Flow(
            start_ms=start,
            end_ms=max(start, end),
            src=_address(src),
            dst=_address(dst),
            sport=_uint(v.get(L4_SRC_PORT, b"\0")) & 0xFFFF,
            dport=_uint(v.get(L4_DST_PORT, b"\0")) & 0xFFFF,
            proto=_uint(v.get(PROTOCOL, b"\0")) & 0xFF,
            bytes=min(_uint(size) * interval, MAX_COUNTER),
            packets=min(_uint(count) * interval, MAX_COUNTER),
            tcp_flags=_uint(v.get(TCP_FLAGS, b"\0")) & 0xFF,
            source="netflow",
            exporter=exporter,
        )
    except ValueError:
        return None


def _sets(data: bytes, offset: int, end: int, header_len: int) -> Iterator[tuple[int, bytes]]:
    """Yield (set id, body) for NetFlow v9 flowsets and IPFIX sets."""
    while offset + 4 <= end:
        set_id, length = struct.unpack_from("!HH", data, offset)
        if length < 4 or offset + length > end:
            raise FlowParseError("set length overruns the datagram")
        yield set_id, data[offset + 4 : offset + length]
        offset += length


def parse_v9(data: bytes, exporter: str, cache: TemplateCache) -> list[Flow]:
    if len(data) < 20:
        raise FlowParseError("short v9 header")
    _, _count, uptime, secs, _seq, source_id = struct.unpack_from("!HHIIII", data, 0)
    base_ms = secs * 1000
    flows: list[Flow] = []
    for set_id, body in _sets(data, 20, len(data), 20):
        if set_id == 0:
            _read_templates(body, exporter, source_id, cache, ipfix=False)
        elif set_id == 1:
            continue  # options templates describe the exporter itself
        elif set_id >= 256:
            template = cache.get(exporter, source_id, set_id)
            if template is not None:  # data before its template: dropped, as RFC 3954 allows
                flows.extend(_decode_records(body, template, exporter, base_ms, uptime, False))
    return flows


def parse_ipfix(data: bytes, exporter: str, cache: TemplateCache) -> list[Flow]:
    if len(data) < 16:
        raise FlowParseError("short IPFIX header")
    _, length, export_time, _seq, domain = struct.unpack_from("!HHIII", data, 0)
    if length > len(data) or length < 16:
        raise FlowParseError("IPFIX length does not match the datagram")
    base_ms = export_time * 1000
    flows: list[Flow] = []
    for set_id, body in _sets(data, 16, length, 16):
        if set_id == 2:
            _read_templates(body, exporter, domain, cache, ipfix=True)
        elif set_id == 3:
            continue
        elif set_id >= 256:
            template = cache.get(exporter, domain, set_id)
            if template is not None:
                flows.extend(_decode_records(body, template, exporter, base_ms, None, True))
    return flows


def parse_datagram(data: bytes, exporter: str, cache: TemplateCache) -> list[Flow]:
    """Decode one UDP datagram of NetFlow v5, v9 or IPFIX."""
    if len(data) < 4:
        raise FlowParseError("datagram too short")
    version = struct.unpack_from("!H", data, 0)[0]
    try:
        if version == 5:
            return parse_v5(data, exporter)
        if version == 9:
            return parse_v9(data, exporter, cache)
        if version == 10:
            return parse_ipfix(data, exporter, cache)
    except struct.error as error:  # belt and braces: every read above is bounds-checked
        raise FlowParseError(f"malformed datagram: {error}") from None
    raise FlowParseError(f"unsupported NetFlow version {version}")

"""ClickHouse access over its HTTP interface (standard library only)."""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any, Protocol

from .model import Flow
from .protocols import is_internal, protocol_name, service_name

IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")


class StoreError(RuntimeError):
    """ClickHouse refused or could not be reached. Messages never contain credentials.

    `retryable` is False when the server rejected the data itself (HTTP 400): sending the same
    batch again can never succeed.
    """

    def __init__(self, message: str, retryable: bool = True) -> None:
        super().__init__(message)
        self.retryable = retryable


class Backend(Protocol):
    """What the rest of the program needs from a database connection."""

    def command(self, sql: str) -> None: ...

    def query(self, sql: str) -> list[dict[str, Any]]: ...

    def insert(self, table: str, rows: Sequence[dict[str, Any]]) -> None: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect could send the credentials headers to another host."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class ClickHouse:
    """Minimal ClickHouse client: DDL, queries (JSONEachRow) and bulk inserts."""

    def __init__(
        self,
        url: str,
        user: str,
        password: str,
        database: str,
        timeout: float = 30.0,
        ca_bundle: Path | None = None,
    ) -> None:
        if not url.startswith(("http://", "https://")):
            raise StoreError("the ClickHouse URL must start with http:// or https://")
        if not IDENTIFIER.match(database):
            raise StoreError("the database name may only contain letters, digits and _")
        self.url = url.rstrip("/")
        self.user = user
        self.password = password
        self.database = database
        self.timeout = timeout
        context = ssl.create_default_context(cafile=str(ca_bundle) if ca_bundle else None)
        self._opener = urllib.request.build_opener(
            _NoRedirect, urllib.request.HTTPSHandler(context=context)
        )

    def _post(self, sql: str, body: bytes | None = None) -> bytes:
        query = urllib.parse.urlencode(
            {"query": sql} if body is not None else {}, quote_via=urllib.parse.quote
        )
        url = f"{self.url}/?{query}" if query else f"{self.url}/"
        data = body if body is not None else sql.encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 - scheme checked in __init__
            url,
            data=data,
            method="POST",
            headers={"X-ClickHouse-User": self.user, "X-ClickHouse-Key": self.password},
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                payload: bytes = response.read()
                return payload
        except urllib.error.HTTPError as error:
            try:
                detail = error.read(600).decode("utf-8", "replace").strip().splitlines()
            finally:
                error.close()  # Python 3.14 warns about the leaked temporary file otherwise
            raise StoreError(
                f"ClickHouse error {error.code}: {detail[0] if detail else ''}",
                retryable=error.code != 400,
            ) from None
        except (urllib.error.URLError, OSError) as error:
            reason = getattr(error, "reason", error)
            raise StoreError(f"cannot reach ClickHouse at {self.url}: {reason}") from None

    def command(self, sql: str) -> None:
        self._post(sql)

    def query(self, sql: str) -> list[dict[str, Any]]:
        raw = self._post(f"{sql.rstrip().rstrip(';')} FORMAT JSONEachRow")
        return [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]

    def insert(self, table: str, rows: Sequence[dict[str, Any]]) -> None:
        if not rows:
            return
        if not IDENTIFIER.match(table):
            raise StoreError("bad table name")
        body = "\n".join(json.dumps(row, separators=(",", ":")) for row in rows).encode("utf-8")
        self._post(f"INSERT INTO {self.database}.{table} FORMAT JSONEachRow", body)


def quote(value: str) -> str:
    """A ClickHouse string literal. Used only for values this program builds itself."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def time_literal(moment: datetime) -> str:
    return f"toDateTime64({quote(moment.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3])}, 3, 'UTC')"


def _stamp(milliseconds: int) -> str:
    seconds, millis = divmod(milliseconds, 1000)
    moment = datetime.fromtimestamp(seconds, tz=UTC)
    return f"{moment:%Y-%m-%d %H:%M:%S}.{millis:03d}"


def flow_row(flow: Flow) -> dict[str, Any]:
    return {
        "start": _stamp(flow.start_ms),
        "end": _stamp(max(flow.start_ms, flow.end_ms)),
        "src_ip": flow.src,
        "dst_ip": flow.dst,
        "src_internal": int(is_internal(flow.src)),
        "dst_internal": int(is_internal(flow.dst)),
        "sport": flow.sport,
        "dport": flow.dport,
        "proto": flow.proto,
        "proto_name": protocol_name(flow.proto),
        "service": service_name(flow.proto, flow.sport, flow.dport),
        "bytes": flow.bytes,
        "packets": flow.packets,
        "tcp_flags": flow.tcp_flags,
        "source": flow.source,
        "exporter": flow.exporter,
    }


@dataclass(frozen=True)
class Anomaly:
    minute: datetime
    kind: str
    subject: str
    value: float
    baseline: float
    score: float
    detail: str = ""


class Store:
    """Everything the program reads from or writes to ClickHouse."""

    def __init__(self, backend: Backend, database: str) -> None:
        if not IDENTIFIER.match(database):
            raise StoreError("the database name may only contain letters, digits and _")
        self.backend = backend
        self.database = database

    def init_schema(self, retention_days: int = 90) -> None:
        if not 1 <= retention_days <= 36_500:
            raise StoreError("retention must be between 1 and 36500 days")
        text = (resources.files("flowpipe") / "schema.sql").read_text(encoding="utf-8")
        text = text.replace("{database}", self.database)
        text = text.replace("{retention_days}", str(retention_days))
        for statement in text.split("\n--;\n"):
            statement = "\n".join(
                line for line in statement.splitlines() if not line.startswith("--")
            ).strip()
            if statement:
                self.backend.command(statement)

    def insert_flows(self, flows: Iterable[Flow]) -> int:
        rows = [flow_row(flow) for flow in flows if flow.plausible()]
        self.backend.insert("flows", rows)
        return len(rows)

    def file_seen(self, sha256: str) -> bool:
        rows = self.backend.query(
            f"SELECT count() AS n FROM {self.database}.ingested_files "
            f"WHERE sha256 = {quote(sha256)}"
        )
        return bool(rows and int(rows[0]["n"]) > 0)

    def record_file(self, sha256: str, name: str, flows: int, packets: int) -> None:
        self.backend.insert(
            "ingested_files",
            [{"sha256": sha256, "name": name[:255], "flows": flows, "packets": packets}],
        )

    def insert_anomalies(self, anomalies: Sequence[Anomaly]) -> None:
        self.backend.insert(
            "anomalies",
            [
                {
                    "minute": a.minute.strftime("%Y-%m-%d %H:%M:%S"),
                    "kind": a.kind,
                    "subject": a.subject[:200],
                    "value": a.value,
                    "baseline": a.baseline,
                    "score": a.score,
                    "detail": a.detail[:500],
                }
                for a in anomalies
            ],
        )

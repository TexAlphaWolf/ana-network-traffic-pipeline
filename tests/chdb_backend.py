"""Test backend: the real ClickHouse SQL engine, embedded (chdb), or a real server."""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any

import pytest

_SESSION: Any = None


def _shared_session() -> Any:
    """chdb allows one session per process, so every test shares it (each has its own database)."""
    global _SESSION
    if _SESSION is None:
        from chdb import session

        _SESSION = session.Session(tempfile.mkdtemp(prefix="flowpipe-chdb-"))
    return _SESSION


class ChdbBackend:
    def __init__(self, database: str) -> None:
        self.session = _shared_session()
        self.database = database

    def command(self, sql: str) -> None:
        self.session.query(sql)

    def query(self, sql: str) -> list[dict[str, Any]]:
        result = self.session.query(f"{sql.rstrip().rstrip(';')} FORMAT JSONEachRow", "JSONEachRow")
        text = str(result).strip()
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    def insert(self, table: str, rows: Any) -> None:
        if not rows:
            return
        columns = ", ".join(rows[0])
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "rows.jsonl")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("\n".join(json.dumps(r) for r in rows))
            self.session.query(
                f"INSERT INTO {self.database}.{table} ({columns}) "
                f"SELECT {columns} FROM file('{path}', 'JSONEachRow')"
            )


def make_backend(database: str = "flowpipe") -> Any:
    """A real ClickHouse if FLOWPIPE_TEST_CLICKHOUSE is set, else embedded chdb, else skip."""
    url = os.environ.get("FLOWPIPE_TEST_CLICKHOUSE")
    if url:
        from flowpipe.store import ClickHouse

        return ClickHouse(
            url,
            os.environ.get("FLOWPIPE_TEST_USER", "default"),
            os.environ.get("FLOWPIPE_TEST_PASSWORD", ""),
            database,
        )
    chdb = pytest.importorskip("chdb")
    del chdb
    return ChdbBackend(database)

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from chdb_backend import make_backend

from flowpipe.store import Store


@pytest.fixture
def store() -> Iterator[Store]:
    """A fresh database per test, on a real ClickHouse engine."""
    database = f"fp_{uuid.uuid4().hex[:10]}"
    backend = make_backend(database)
    result = Store(backend, database)
    result.init_schema(retention_days=3650)
    yield result
    try:
        backend.command(f"DROP DATABASE IF EXISTS {database}")
    except Exception:  # noqa: S110 - cleanup is best effort
        pass

"""Runtime configuration, read from environment variables (all prefixed with FLOWPIPE_)."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

from .anomaly import SpikeSettings
from .store import IDENTIFIER


class ConfigError(ValueError):
    """A setting is missing or invalid."""


@dataclass(frozen=True)
class Settings:
    clickhouse_url: str = "http://localhost:8123"
    user: str = "default"
    password: str = ""
    database: str = "flowpipe"
    retention_days: int = 90
    ca_bundle: Path | None = None
    batch_size: int = 5000
    flush_seconds: float = 5.0
    idle_seconds: int = 15
    active_seconds: int = 60
    listen: str = "127.0.0.1"
    port: int = 2055
    allowed_exporters: tuple[str, ...] = ()
    allow_any_exporter: bool = False
    anonymise_key: str | None = None
    spikes: SpikeSettings = SpikeSettings()
    scan_threshold: int = 100


def _whole(name: str, default: int, minimum: int = 0, maximum: int = 10**9) -> int:
    raw = os.environ.get(name, "").strip() or str(default)
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a whole number, got {raw!r}") from None
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return value


def _decimal(name: str, default: float, minimum: float) -> float:
    raw = os.environ.get(name, "").strip() or str(default)
    try:
        value = float(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from None
    if value < minimum:
        raise ConfigError(f"{name} must be at least {minimum}")
    return value


def _flag(name: str) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw or raw in {"0", "false", "no", "off"}:
        return False
    if raw in {"1", "true", "yes", "on"}:
        return True
    raise ConfigError(f"{name} must be true or false, got {raw!r}")


def _text(name: str) -> str | None:
    return os.environ.get(name, "").strip() or None


def parse_networks(text: str) -> tuple[str, ...]:
    """A comma separated list of addresses or CIDR ranges, validated."""
    result = []
    for item in text.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            result.append(str(ipaddress.ip_network(item, strict=False)))
        except ValueError:
            raise ConfigError(
                f"FLOWPIPE_ALLOWED_EXPORTERS: {item!r} is not an address or range"
            ) from None
    return tuple(result)


def load_settings() -> Settings:
    database = _text("FLOWPIPE_DATABASE") or "flowpipe"
    if not IDENTIFIER.match(database):
        raise ConfigError("FLOWPIPE_DATABASE may only contain letters, digits and _")
    url = _text("FLOWPIPE_CLICKHOUSE_URL") or "http://localhost:8123"
    if not url.startswith(("http://", "https://")):
        raise ConfigError("FLOWPIPE_CLICKHOUSE_URL must start with http:// or https://")
    key = _text("FLOWPIPE_ANONYMISE_KEY")
    if key is not None and len(key) < 8:
        raise ConfigError("FLOWPIPE_ANONYMISE_KEY must have at least 8 characters")
    bundle = _text("FLOWPIPE_CA_BUNDLE")
    return Settings(
        clickhouse_url=url,
        user=_text("FLOWPIPE_CLICKHOUSE_USER") or "default",
        password=os.environ.get("FLOWPIPE_CLICKHOUSE_PASSWORD", ""),
        database=database,
        retention_days=_whole("FLOWPIPE_RETENTION_DAYS", 90, 1, 36_500),
        ca_bundle=Path(bundle) if bundle else None,
        batch_size=_whole("FLOWPIPE_BATCH_SIZE", 5000, 1, 100_000),
        flush_seconds=_decimal("FLOWPIPE_FLUSH_SECONDS", 5.0, 0.5),
        idle_seconds=_whole("FLOWPIPE_IDLE_SECONDS", 15, 1, 3600),
        active_seconds=_whole("FLOWPIPE_ACTIVE_SECONDS", 60, 1, 86_400),
        listen=_text("FLOWPIPE_LISTEN") or "127.0.0.1",
        port=_whole("FLOWPIPE_PORT", 2055, 1, 65_535),
        allowed_exporters=parse_networks(os.environ.get("FLOWPIPE_ALLOWED_EXPORTERS", "")),
        allow_any_exporter=_flag("FLOWPIPE_ALLOW_ANY_EXPORTER"),
        anonymise_key=key,
        spikes=SpikeSettings(
            window=_whole("FLOWPIPE_SPIKE_WINDOW_MIN", 30, 5, 1440),
            threshold=_decimal("FLOWPIPE_SPIKE_THRESHOLD", 6.0, 1.0),
            min_bytes=_whole("FLOWPIPE_SPIKE_MIN_BYTES", 1_000_000, 0),
        ),
        scan_threshold=_whole("FLOWPIPE_SCAN_THRESHOLD", 100, 2),
    )


def load_env_file(path: Path = Path(".env")) -> bool:
    """Read KEY=VALUE lines from `path` into the environment (real variables win)."""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError:
        return False
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if value[:1] in ("'", '"') and (close := value.find(value[0], 1)) > 0:
            value = value[1:close]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        os.environ.setdefault(key.strip(), value)
    return True


def make_store(settings: Settings):  # type: ignore[no-untyped-def]
    from .store import ClickHouse, Store

    backend = ClickHouse(
        settings.clickhouse_url,
        settings.user,
        settings.password,
        settings.database,
        ca_bundle=settings.ca_bundle,
    )
    return Store(backend, settings.database)

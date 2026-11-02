from __future__ import annotations

from pathlib import Path

import pytest

from flowpipe.anonymise import Anonymiser
from flowpipe.config import (
    ConfigError,
    load_env_file,
    load_settings,
    parse_networks,
)
from flowpipe.protocols import is_internal, protocol_name, service_name


@pytest.mark.parametrize(
    "address, expected",
    [
        ("10.1.2.3", True), ("192.168.1.9", True), ("172.20.0.1", True), ("100.64.0.1", True),
        ("127.0.0.1", True), ("169.254.1.1", True), ("224.0.0.251", True), ("fe80::1", True),
        ("fd12::1", True), ("::ffff:10.0.0.1", True),
        ("8.8.8.8", False), ("203.0.113.5", False), ("198.51.100.1", False),
        ("2001:db8::1", False), ("not an ip", False),
    ],
)  # fmt: skip
def test_internal_external_split(address, expected):
    assert is_internal(address) is expected


def test_names():
    assert protocol_name(6) == "TCP" and protocol_name(99) == "proto-99"
    assert service_name(6, 51000, 443) == "https"
    assert service_name(6, 443, 51000) == "https"
    assert service_name(17, 53, 53) == "dns"
    assert service_name(6, 40000, 40001) == "other"
    assert service_name(1, 0, 0x0800) == "icmp" and service_name(58, 0, 0) == "icmpv6"
    assert service_name(47, 0, 0) == "other"
    assert service_name(6, 22, 8080) == "ssh"  # the lower known port wins


def test_anonymiser_is_deterministic_keyed_and_keeps_the_split():
    one, two = Anonymiser("secret-key-1"), Anonymiser("secret-key-2")
    a = one("192.168.1.10")
    assert a == one("192.168.1.10") and a != two("192.168.1.10")
    assert is_internal(a) and a.startswith("10.")
    external = one("203.0.113.5")
    assert not is_internal(external) and external.startswith("198.")
    assert is_internal(one("fe80::1")) and not is_internal(one("2001:db8::7"))
    assert one("garbage") == "invalid"
    assert "192.168.1.10" not in a
    with pytest.raises(ValueError):
        Anonymiser("short")


def test_anonymiser_does_not_collide_on_a_whole_subnet():
    mapper = Anonymiser("secret-key-1")
    mapped = {mapper(f"10.20.0.{n}") for n in range(1, 255)}
    assert len(mapped) == 254


def test_settings_defaults_and_overrides(monkeypatch):
    for name in list(__import__("os").environ):
        if name.startswith("FLOWPIPE_"):
            monkeypatch.delenv(name)
    settings = load_settings()
    assert settings.database == "flowpipe" and settings.port == 2055
    assert settings.listen == "127.0.0.1" and settings.allowed_exporters == ()
    monkeypatch.setenv("FLOWPIPE_ALLOWED_EXPORTERS", "192.168.1.254, 10.0.0.0/24")
    monkeypatch.setenv("FLOWPIPE_PORT", "9995")
    monkeypatch.setenv("FLOWPIPE_ALLOW_ANY_EXPORTER", "yes")
    monkeypatch.setenv("FLOWPIPE_CA_BUNDLE", "/etc/ca.pem")
    settings = load_settings()
    assert settings.allowed_exporters == ("192.168.1.254/32", "10.0.0.0/24")
    assert settings.port == 9995 and settings.allow_any_exporter
    assert settings.ca_bundle == Path("/etc/ca.pem")  # \etc\ca.pem on Windows


@pytest.mark.parametrize(
    "name, value",
    [
        ("FLOWPIPE_PORT", "abc"), ("FLOWPIPE_PORT", "70000"), ("FLOWPIPE_DATABASE", "a;drop"),
        ("FLOWPIPE_CLICKHOUSE_URL", "ftp://x"), ("FLOWPIPE_ANONYMISE_KEY", "short"),
        ("FLOWPIPE_ALLOWED_EXPORTERS", "not-an-ip"), ("FLOWPIPE_ALLOW_ANY_EXPORTER", "maybe"),
        ("FLOWPIPE_FLUSH_SECONDS", "x"), ("FLOWPIPE_FLUSH_SECONDS", "0.1"),
        ("FLOWPIPE_RETENTION_DAYS", "0"),
    ],
)  # fmt: skip
def test_settings_reject_bad_values(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(ConfigError):
        load_settings()


def test_parse_networks_ignores_empty_items():
    assert parse_networks(" , 10.0.0.1 ,") == ("10.0.0.1/32",)


def test_env_file(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_text(
        "# comment\nFLOWPIPE_A=1\nFLOWPIPE_B='two words' # note\nFLOWPIPE_C=3 # note\n"
        "FLOWPIPE_D=already\nbadline\n",
        encoding="utf-8-sig",
    )
    monkeypatch.setenv("FLOWPIPE_D", "real")
    for name in ("FLOWPIPE_A", "FLOWPIPE_B", "FLOWPIPE_C"):
        monkeypatch.delenv(name, raising=False)
    assert load_env_file(path) is True
    import os

    assert os.environ["FLOWPIPE_A"] == "1" and os.environ["FLOWPIPE_B"] == "two words"
    assert os.environ["FLOWPIPE_C"] == "3" and os.environ["FLOWPIPE_D"] == "real"
    for name in ("FLOWPIPE_A", "FLOWPIPE_B", "FLOWPIPE_C"):
        monkeypatch.delenv(name)
    assert load_env_file(tmp_path / "missing") is False

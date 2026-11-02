"""Protocol and service names, and the internal/external split."""

from __future__ import annotations

import ipaddress

PROTOCOLS = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6-encap",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}

# Well-known ports only: enough to label home and small-office traffic.
SERVICES = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    80: "http",
    110: "pop3",
    123: "ntp",
    137: "netbios",
    138: "netbios",
    139: "netbios",
    143: "imap",
    161: "snmp",
    162: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    514: "syslog",
    587: "submission",
    636: "ldaps",
    853: "dns-over-tls",
    873: "rsync",
    993: "imaps",
    995: "pop3s",
    1194: "openvpn",
    1883: "mqtt",
    1900: "ssdp",
    3306: "mysql",
    3389: "rdp",
    5060: "sip",
    5353: "mdns",
    5432: "postgres",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    8883: "mqtt-tls",
    51820: "wireguard",
}


def protocol_name(proto: int) -> str:
    return PROTOCOLS.get(proto, f"proto-{proto}")


def service_name(proto: int, sport: int, dport: int) -> str:
    """Name of the service a flow belongs to, or "other".

    Only TCP, UDP and SCTP have ports. The lower known port wins, because clients use
    random high ports and servers use the well-known one.
    """
    if proto == 1:
        return "icmp"
    if proto == 58:
        return "icmpv6"
    if proto not in (6, 17, 132):
        return "other"
    known = [SERVICES[port] for port in sorted((dport, sport)) if port in SERVICES]
    return known[0] if known else "other"


_INTERNAL = tuple(
    ipaddress.ip_network(net)
    for net in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
        "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
    )
)  # fmt: skip


def is_internal(address: str) -> bool:
    """True for private, shared (CGNAT), link-local, loopback and multicast addresses.

    Documentation ranges (192.0.2.0/24 and friends) count as external on purpose: Python's
    own `is_private` would call them private, which would hide them from "internet" reports.
    """
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return any(ip in network for network in _INTERNAL if network.version == ip.version)

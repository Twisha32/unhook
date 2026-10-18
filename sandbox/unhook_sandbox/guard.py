"""Egress policy shared by the tracer and the proxy.

The rule is simple: a request may only reach addresses on the public internet.
Loopback, RFC 1918, link-local (which includes the cloud metadata address),
CGNAT, multicast and friends are refused. We judge the addresses a name
*resolves to*, never the name itself, because the person who owns a phishing
domain also owns its DNS.
"""

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

# Phishing kits almost always sit on the default ports. Refusing the rest keeps
# the sandbox from being pointed at somebody's Redis or SSH by accident.
ALLOWED_PORTS = frozenset({80, 443, 8080, 8443})

_NAT64 = ipaddress.ip_network("64:ff9b::/96")


class EgressError(Exception):
    """The sandbox won't (or can't) make this request."""


class Blocked(EgressError):
    """Refused by policy."""


class Unresolvable(EgressError):
    """The name doesn't resolve, which is not the same as being refused."""


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int

    @property
    def authority(self) -> str:
        default = 443 if self.scheme == "https" else 80
        host = f"[{self.host}]" if ":" in self.host else self.host
        return host if self.port == default else f"{host}:{self.port}"


def ip_allowed(addr: str, allow_private: bool = False) -> bool:
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        # Tunnelling prefixes carry an IPv4 address; judge that instead.
        if ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        elif ip.sixtofour:
            ip = ip.sixtofour
        elif ip in _NAT64:
            ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip.is_multicast or ip.is_unspecified:
        return False
    return True if allow_private else ip.is_global


def parse_target(url: str, ports: frozenset[int] = ALLOWED_PORTS) -> Target:
    """Syntax-level checks that don't need the network."""
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError as exc:
        raise Blocked(f"malformed URL ({exc})") from None
    if parts.scheme not in ("http", "https"):
        raise Blocked("only http and https links are traced")
    if parts.username or parts.password:
        raise Blocked("URLs with embedded credentials are not followed")
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise Blocked("URL has no host")
    port = port or (443 if parts.scheme == "https" else 80)
    if port not in ports:
        raise Blocked(f"port {port} is not on the allow list")
    return Target(parts.scheme, host, port)


def check_literal(host: str, allow_private: bool = False) -> None:
    """Refuse an IP-literal host outright. Used where DNS isn't ours to resolve."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return
    if not ip_allowed(host, allow_private):
        raise Blocked(f"{host} is not a public address")


def resolve(host: str, port: int, allow_private: bool = False) -> list[str]:
    """Resolve and vet every address. One bad answer refuses the whole name, since a
    hostile resolver can hand back a mix and hope we pick the wrong one."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        raise Unresolvable(f"could not resolve {host}") from None
    addrs = list(dict.fromkeys(info[4][0] for info in infos))
    if not addrs:
        raise Unresolvable(f"no addresses for {host}")
    for addr in addrs:
        if not ip_allowed(addr, allow_private):
            raise Blocked(f"{host} resolves to a non-public address")
    return addrs

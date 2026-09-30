"""Destination policy for fetching arbitrary third-party URLs (SSRF defence).

Unlike the fixed-host provider APIs, research sources are URLs taken from advisories and search
results, i.e. attacker-influenced. Before any connection the URL must pass `validate_url`, and its
hostname must resolve ONLY to public addresses (`resolve_public`). The fetcher then connects to the
address it validated, not to the name, so DNS cannot change its answer between check and use.
"""

import ipaddress
import socket
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

MAX_URL_LENGTH = 2048
DEFAULT_PORTS = (80, 443)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int], Sequence[str]]

_BLOCKED_SUFFIXES = (
    ".localhost", ".local", ".internal", ".intranet", ".lan", ".home", ".corp", ".private",
    ".localdomain", ".home.arpa", ".onion",
)  # fmt: skip
_BLOCKED_HOSTS = frozenset({"localhost", "metadata", "metadata.google.internal"})


class BlockedDestination(Exception):
    """The URL or its resolved address is not allowed to be fetched. `code` is a short slug."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str  # IDNA (ASCII) form
    port: int
    path_and_query: str

    @property
    def origin(self) -> str:
        default = 443 if self.scheme == "https" else 80
        return f"{self.scheme}://{self.host}" + ("" if self.port == default else f":{self.port}")

    @property
    def url(self) -> str:
        return self.origin + self.path_and_query


def system_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


def _embedded_ipv4(address: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """IPv4 addresses hidden inside IPv6 forms (mapped, NAT64, 6to4) must pass the same checks."""
    if address.ipv4_mapped is not None:
        return address.ipv4_mapped
    if address.sixtofour is not None:
        return address.sixtofour
    if address in ipaddress.ip_network("64:ff9b::/96"):
        return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    return None


def is_public_ip(value: str) -> bool:
    try:
        address: IPAddress = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(address)
        if embedded is not None:
            return is_public_ip(str(embedded))
        if address in ipaddress.ip_network("2001::/32"):  # Teredo tunnelling
            return False
    return address.is_global and not address.is_multicast


def validate_url(
    url: str,
    *,
    allowed_ports: Sequence[int] = DEFAULT_PORTS,
    allowed_schemes: Sequence[str] = ("http", "https"),
) -> Target:
    if not isinstance(url, str) or not url or len(url) > MAX_URL_LENGTH:
        raise BlockedDestination("invalid_url")
    if any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in url):
        raise BlockedDestination("invalid_url", "control or whitespace character")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise BlockedDestination("invalid_url") from exc
    scheme = parts.scheme.lower()
    if scheme not in allowed_schemes:
        raise BlockedDestination("scheme_not_allowed", scheme)
    if parts.username is not None or parts.password is not None:
        raise BlockedDestination("credentials_in_url")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise BlockedDestination("invalid_url", "no host")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise BlockedDestination("invalid_url", "bad hostname") from exc

    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise BlockedDestination("ip_literal_host")
    labels = host.split(".")
    if len(labels) < 2:
        raise BlockedDestination("single_label_host")
    if not any(ch.isalpha() for ch in labels[-1]):
        # "2130706433", "0x7f.1", "127.1": numeric forms that resolvers turn into IPs.
        raise BlockedDestination("ip_literal_host")
    if host in _BLOCKED_HOSTS or host.endswith(_BLOCKED_SUFFIXES):
        raise BlockedDestination("internal_hostname")

    effective_port = port or (443 if scheme == "https" else 80)
    if effective_port not in allowed_ports:
        raise BlockedDestination("port_not_allowed", str(effective_port))
    path = parts.path or "/"
    return Target(scheme, host, effective_port, path + (f"?{parts.query}" if parts.query else ""))


def resolve_public(
    host: str, port: int, resolver: Resolver = system_resolver, *, allow_private: bool = False
) -> list[str]:
    """Resolve `host`; every returned address must be public (a mix is treated as hostile)."""
    try:
        addresses = list(resolver(host, port))
    except (OSError, UnicodeError) as exc:
        raise BlockedDestination("dns_failure") from exc
    if not addresses:
        raise BlockedDestination("dns_failure", "no addresses")
    if not allow_private:
        for address in addresses:
            if not is_public_ip(address):
                raise BlockedDestination("non_public_address", address)
    return addresses

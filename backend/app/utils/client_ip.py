"""Work out the real client address behind trusted reverse proxies / the web app.

`X-Forwarded-For` is only believed when the TCP peer is itself a trusted proxy, and then the
right-most address that is not trusted is taken (anything to its left is client-controlled and
could be spoofed). Otherwise the header is ignored entirely.
"""

import ipaddress
from collections.abc import Sequence
from functools import lru_cache

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@lru_cache(maxsize=32)
def parse_networks(entries: tuple[str, ...]) -> tuple[IPNetwork, ...]:
    """Parse addresses/CIDRs (a bare address means a single host). Raises ValueError if invalid."""
    return tuple(
        ipaddress.ip_network(entry.strip(), strict=False) for entry in entries if entry.strip()
    )


def _parse(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def _is_trusted(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address, trusted: Sequence[IPNetwork]
) -> bool:
    return any(address.version == network.version and address in network for network in trusted)


def client_ip(peer: str | None, forwarded_for: str | None, trusted: Sequence[IPNetwork]) -> str:
    if not peer:
        return "unknown"
    peer_address = _parse(peer)
    if not trusted or peer_address is None or not _is_trusted(peer_address, trusted):
        return peer
    if not forwarded_for:
        return peer
    for candidate in reversed(forwarded_for.split(",")):
        address = _parse(candidate)
        if address is None:
            return peer  # a malformed header cannot be trusted at all
        if not _is_trusted(address, trusted):
            return str(address)
    return peer  # every hop was one of ours

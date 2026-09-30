import pytest

from app.config import Settings
from app.utils.client_ip import client_ip, parse_networks

TRUSTED = parse_networks(("10.0.0.0/8", "172.16.0.5", "fd00::/8"))


def test_without_trusted_proxies_the_header_is_ignored() -> None:
    assert client_ip("203.0.113.9", "1.2.3.4", ()) == "203.0.113.9"


def test_header_from_an_untrusted_peer_is_ignored_so_it_cannot_be_spoofed() -> None:
    assert client_ip("203.0.113.9", "1.2.3.4", TRUSTED) == "203.0.113.9"


@pytest.mark.parametrize(
    ("peer", "header", "expected"),
    [
        ("10.1.2.3", "198.51.100.7", "198.51.100.7"),
        ("10.1.2.3", "  198.51.100.7  ", "198.51.100.7"),
        ("172.16.0.5", "198.51.100.7, 10.9.9.9", "198.51.100.7"),  # our own proxy hop is skipped
        ("10.1.2.3", "6.6.6.6, 198.51.100.7", "198.51.100.7"),  # a spoofed prefix is ignored
        ("10.1.2.3", "2001:db8::1", "2001:db8::1"),
        ("fd00::1", "198.51.100.7", "198.51.100.7"),
    ],
)
def test_right_most_untrusted_address_is_the_client(peer: str, header: str, expected: str) -> None:
    assert client_ip(peer, header, TRUSTED) == expected


@pytest.mark.parametrize(
    "header", [None, "", "10.9.9.9, 10.8.8.8", "garbage", "1.2.3.4, not-an-ip", "1.2.3.4,,"]
)
def test_falls_back_to_the_peer_when_the_header_is_missing_all_trusted_or_malformed(
    header: str | None,
) -> None:
    assert client_ip("10.1.2.3", header, TRUSTED) == "10.1.2.3"


def test_missing_peer() -> None:
    assert client_ip(None, "1.2.3.4", TRUSTED) == "unknown"


def test_a_non_ip_peer_is_used_as_is() -> None:
    assert client_ip("testclient", "1.2.3.4", TRUSTED) == "testclient"  # Starlette's TestClient


def test_settings_parse_and_validate_trusted_proxies(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    monkeypatch.setenv("TRUSTED_PROXIES", "10.0.0.0/8, 172.16.0.5 ,")
    assert Settings(_env_file=None).trusted_proxies == ["10.0.0.0/8", "172.16.0.5"]  # type: ignore[call-arg]
    monkeypatch.setenv("TRUSTED_PROXIES", "10.0.0.0/8, not-an-address")
    with pytest.raises(ValueError, match="TRUSTED_PROXIES"):
        Settings(_env_file=None)  # type: ignore[call-arg]

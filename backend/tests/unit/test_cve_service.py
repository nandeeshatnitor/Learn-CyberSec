import pytest

from app.repositories import CVERepository
from app.services import CVEService, InvalidInputError, NotFoundError


@pytest.fixture
def service(db) -> CVEService:
    return CVEService(CVERepository(db), max_page_size=10)


def test_get_cve_normalises_id(service, make_cve) -> None:
    make_cve("CVE-2021-44228")
    assert service.get_cve(" cve-2021-44228 ").cve_id == "CVE-2021-44228"


def test_get_cve_rejects_malformed_id(service) -> None:
    with pytest.raises(InvalidInputError):
        service.get_cve("not-a-cve")


def test_get_cve_not_found(service) -> None:
    with pytest.raises(NotFoundError):
        service.get_cve("CVE-1999-0001")


def test_search_strips_control_chars_and_whitespace(service, make_cve) -> None:
    make_cve("CVE-2021-44228")
    query, items, total = service.search("  Log\x004j2 ", limit=5, offset=0)
    assert query == "Log4j2"
    assert total == len(items) == 1


@pytest.mark.parametrize("query", ["", "   ", "\x00\x01", "x" * 101])
def test_search_rejects_empty_or_oversized_queries(service, query: str) -> None:
    with pytest.raises(InvalidInputError):
        service.search(query, limit=5, offset=0)


@pytest.mark.parametrize(("limit", "offset"), [(0, 0), (11, 0), (5, -1)])
def test_search_enforces_pagination_bounds(service, limit: int, offset: int) -> None:
    with pytest.raises(InvalidInputError):
        service.search("log4j", limit=limit, offset=offset)


def test_search_treats_like_wildcards_literally(service, make_cve) -> None:
    make_cve("CVE-2021-44228", description="Remote code execution")
    _, items, total = service.search("%", limit=5, offset=0)
    assert (items, total) == ([], 0)
    _, items, _ = service.search("_emote", limit=5, offset=0)
    assert items == []


def test_exact_cve_id_ranks_first(service, make_cve) -> None:
    make_cve("CVE-2021-44228")
    make_cve("CVE-2021-442280", description="mentions CVE-2021-44228 in text")
    _, items, total = service.search("cve-2021-44228", limit=5, offset=0)
    assert total == 2
    assert items[0].cve_id == "CVE-2021-44228"

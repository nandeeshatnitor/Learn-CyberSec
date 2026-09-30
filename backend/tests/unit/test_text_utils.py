from app.utils.text import escape_like, strip_control_chars


def test_strip_control_chars_keeps_printable_and_whitespace() -> None:
    assert strip_control_chars("a\x00b\x1bc\x7fd\te\nf") == "abcd\te\nf"


def test_escape_like_escapes_wildcards_and_escape_char() -> None:
    assert escape_like("100%_done\\") == "100\\%\\_done\\\\"

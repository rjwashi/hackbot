import pytest

from helpers import count_words, slugify


@pytest.mark.parametrize(
    "text,expected",
    [
        ("Hello World", "hello-world"),
        ("  Leading and trailing  ", "leading-and-trailing"),
        ("already-kebab", "already-kebab"),
        ("Numeric 42 test", "numeric-42-test"),
        ("!!!", ""),
        ("--a--b--", "a-b"),
    ],
)
def test_slugify(text, expected):
    assert slugify(text) == expected


@pytest.mark.parametrize(
    "text,expected",
    [
        ("", 0),
        ("one two three", 3),
        ("   spaced   out   ", 2),
    ],
)
def test_count_words(text, expected):
    assert count_words(text) == expected
import pytest  # test framework: parametrization and assertions

from helpers import count_words, slugify  # import the functions under test


@pytest.mark.parametrize(  # run the same test body over many input/output pairs
    "text,expected",  # names for the two parameters
    [
        ("Hello World", "hello-world"),  # basic case: lowercase + dash for space
        ("  Leading and trailing  ", "leading-and-trailing"),  # surrounding whitespace is trimmed
        ("already-kebab", "already-kebab"),  # an already-slugged string is unchanged
        ("Numeric 42 test", "numeric-42-test"),  # digits are preserved
        ("!!!", ""),  # punctuation only -> empty string
        ("--a--b--", "a-b"),  # runs of separators collapse to single dashes, edges trimmed
    ],
)
def test_slugify(text, expected):  # parametrized slugify test
    assert slugify(text) == expected  # the function result must match the expected slug


@pytest.mark.parametrize(  # parametrize the word-counter test as well
    "text,expected",  # parameters: input text and expected count
    [
        ("", 0),  # empty string has zero words
        ("one two three", 3),  # three whitespace-separated words
        ("   spaced   out   ", 2),  # split() collapses whitespace, so padding doesn't add words
    ],
)
def test_count_words(text, expected):  # parametrized count_words test
    assert count_words(text) == expected  # the count must match

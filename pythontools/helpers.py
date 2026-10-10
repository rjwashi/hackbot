"""Helpers that are easier in Python than Go.

Each helper is a module with a ``main()`` that reads arguments from ``sys.argv``
and prints a result to stdout, so Go can call it via ``exec.Command``:

    go:   hackbot py helpers slugify "Hello World" -> hello-world
"""

import sys  # sys.argv and sys.exit are used here


def slugify(text: str) -> str:  # public helper: turn arbitrary text into a URL/ID-safe slug
    """Lowercase, keep [a-z0-9-], collapse runs of '-'."""
    out = []  # list of characters to join at the end (cheaper than string += in a loop)
    last_dash = False  # track whether the previous emitted char was a dash, to collapse runs
    for ch in text.lower():  # normalize case first, then inspect each character
        if ch.isalnum():  # letters and digits are kept as-is
            out.append(ch)  # keep the alphanumeric character
            last_dash = False  # a real character resets the dash state
        elif not last_dash:  # any non-alphanumeric char becomes one dash...
            out.append("-")  # ...but only if the previous emitted char wasn't already a dash
            last_dash = True  # remember we just emitted a dash
    return "".join(out).strip("-")  # join the chars and trim leading/trailing dashes


def count_words(text: str) -> int:  # public helper: count whitespace-separated words
    return len(text.split())  # str.split() with no args collapses runs of whitespace, so this ignores padding


def main(argv: list[str]) -> int:  # CLI entry point; returns a process exit code
    if len(argv) < 2:  # need at least a helper name...
        print("usage: helpers.py <slugify|count_words> <text...>", file=sys.stderr)  # ...print usage to stderr
        return 2  # conventional "usage error" exit code
    command, *rest = argv[1:]  # split the first arg (helper name) from the rest
    text = " ".join(rest)  # re-join the remaining args into the input text
    if command == "slugify":  # dispatch: slugify
        print(slugify(text))  # print the result to stdout (Go captures this)
        return 0  # success
    if command == "count_words":  # dispatch: count_words
        print(count_words(text))  # print the numeric count
        return 0  # success
    print(f"unknown helper: {command}", file=sys.stderr)  # unknown helper...
    return 2  # ...usage error


if __name__ == "__main__":  # only run when executed as a script, not when imported by tests
    sys.exit(main(sys.argv))  # run main and exit with its return code

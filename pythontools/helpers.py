"""Helpers that are easier in Python than Go.

Each helper is a module with a ``main()`` that reads arguments from ``sys.argv``
and prints a result to stdout, so Go can call it via ``exec.Command``:

    go:   hackbot py helpers slugify "Hello World" -> hello-world
"""

import sys


def slugify(text: str) -> str:
    """Lowercase, keep [a-z0-9-], collapse runs of '-'."""
    out = []
    last_dash = False
    for ch in text.lower():
        if ch.isalnum():
            out.append(ch)
            last_dash = False
        elif not last_dash:
            out.append("-")
            last_dash = True
    return "".join(out).strip("-")


def count_words(text: str) -> int:
    return len(text.split())


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: helpers.py <slugify|count_words> <text...>", file=sys.stderr)
        return 2

    command, *rest = argv[1:]
    text = " ".join(rest)

    if command == "slugify":
        print(slugify(text))
        return 0
    if command == "count_words":
        print(count_words(text))
        return 0

    print(f"unknown helper: {command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
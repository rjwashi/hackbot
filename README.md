# hackbot

A Go-first bot with Python helpers, by [@rjwashi](https://github.com/rjwashi).

**Design:** Go owns the core bot logic (config, loop, I/O). Anything Go can't
do cleanly is delegated to small, self-contained Python helpers under
`pythontools/`, invoked via `exec.Command`.

## Layout

```
hackbot/
├── main.go                 # CLI entry point (hello | run | py | version)
├── internal/
│   ├── bot/                # core bot loop + Python escape hatch
│   └── config/             # JSON config + env-var overrides
├── pythontools/            # Python helpers (slugify, count_words, ...)
├── .github/workflows/ci.yml  # CI: gofmt, vet, build, test + pytest
└── README.md
```

## Requirements

- [Go](https://go.dev/dl/) 1.27+
- Python 3.11+ (only needed for `hackbot py ...`)

## Build & run

```bash
go build -o bin/hackbot.exe .
./bin/hackbot.exe hello
./bin/hackbot.exe run -config hackbot.json   # optional; defaults are built in
./bin/hackbot.exe version
```

### Python helpers

```bash
./bin/hackbot.exe py helpers.py slugify "Hello World"   # -> hello-world
```

## Configuration

Optional JSON file (see `-config`) with env-var overrides:

| File key | Env var | Default |
|---|---|---|
| `name` | `HACKBOT_NAME` | `hackbot` |
| `interval_seconds` | `HACKBOT_INTERVAL_SECONDS` | `60` |
| `python_cmd` | `HACKBOT_PYTHON_CMD` | `python` |

## Testing

```bash
go test ./... -race -cover     # Go tests
python -m pytest pythontools   # Python helper tests
```

CI runs both on every push and pull request.

## Status

Early scaffold — core loop and helpers are in place; real bot features are
tracked as issues in this repo.
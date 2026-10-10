# hackbot

A Go-first bot with Python helpers, by [@rjwashi](https://github.com/rjwashi).

**Design:** Go owns the core bot logic (config, loop, I/O, analysis). Anything Go
can't do cleanly is delegated to small, self-contained Python helpers under
`pythontools/`, invoked via `exec.Command`.

## Layout

```
hackbot/
├── main.go                 # CLI entry point
├── internal/
│   ├── bot/                # core bot loop + Python escape hatch
│   ├── config/             # JSON config + env-var overrides
│   ├── nmap/               # nmap XML parsing + rule-based risk analysis
│   ├── scan/               # GUARDED nmap runner (allowlist enforced)
│   └── agent/              # pipeline: analyze -> [LLM] -> [issues]
├── pythontools/            # Python helpers (slugify, count_words, ...)
├── .github/workflows/ci.yml  # CI: gofmt, vet, build, test + pytest
└── README.md
```

## Requirements

- [Go](https://go.dev/dl/) 1.27+
- Python 3.11+ (only needed for `hackbot py ...`)
- [nmap](https://nmap.org/download.html) (only needed for `hackbot nmap scan ...`)

## Build & run

```bash
go build -o bin/hackbot.exe .
./bin/hackbot.exe hello
./bin/hackbot.exe run
./bin/hackbot.exe version
```

### Python helpers

```bash
./bin/hackbot.exe py helpers.py slugify "Hello World"   # -> hello-world
```

## nmap agent

hackbot can ingest nmap results and run a modular analysis pipeline:

```
parse -> rule-based risk report -> [LLM explanation] -> [GitHub issues]
```

### Commands

```bash
# Parse an nmap XML file and list hosts/ports
hackbot nmap parse   scan.xml

# Rule-based risk report (flags risky exposed services)
hackbot nmap analyze scan.xml

# NSE script (recon) output: banners, page titles, headers, keys
hackbot nmap recon   scan.xml

# GUARDED scan of an allowlisted target, then analyze + recon
hackbot nmap scan    192.168.1.10

# Full pipeline (flags work anywhere on the line)
hackbot nmap pipeline scan.xml -llm -issues -repo rjwashi/hackbot -min-severity high

# Add -json to any nmap command for machine-readable output
hackbot nmap analyze scan.xml -json
```

Produce the XML input with nmap yourself:

```bash
nmap -sV -oX scan.xml 192.168.1.0/24
```

### Risk rules

`internal/nmap` flags commonly-sensitive exposed services (Docker API, Redis,
MongoDB, SMB, RDP, databases, …) with a severity, and lists other open ports as
`INFO`. It is conservative: it reports *exposure*, not a confirmed vulnerability.

### NSE recon

hackbot parses Nmap Scripting Engine (NSE) output from XML and can run a safe
recon profile during guarded scans. Ingestion works on any XML containing
`<script>` output (per-port or host-level `<hostscript>`):

```bash
hackbot nmap recon scan.xml          # list script results
hackbot nmap recon scan.xml -json    # machine-readable
```

When scanning, a conservative default profile runs
(`banner`, `http-title`, `http-headers`, `ssh-hostkey`, `ssl-cert`). Override it
with `-scripts`, or disable it with `-scripts none`:

```bash
hackbot nmap scan 192.168.1.10 -scripts safe,default   # nmap categories work too
hackbot nmap scan 192.168.1.10 -scripts none           # ports/services only
hackbot nmap scan 192.168.1.10 -script-args http.useragent=hackbot
```

NSE output is also folded into the pipeline report (`nmap pipeline`) and the LLM
prompt.

### LLM stage

Set an OpenAI-compatible endpoint (e.g. OpenCode Zen) and `-llm` will ask the
model to prioritize findings and suggest remediation:

```bash
export HACKBOT_LLM_BASE_URL=https://opencode.ai/zen/v1
export HACKBOT_LLM_API_KEY=...
export HACKBOT_LLM_MODEL=step-5-preview-free
hackbot nmap pipeline scan.xml -llm
```

If the LLM isn't configured, the stage is skipped with a note (no error).

### Actions stage

`-issues` files one GitHub issue per finding at or above `-min-severity`
(default `high`), capped by `-max-issues` (default 10). **Issue creation is
dry-run by default**; pass `-dry-run=false` to actually create issues via `gh`.
Findings can also just be exported with `-json` for your own tooling.

## ⚠️ Authorized use only

Scanning networks you do not own or lack written permission to test is illegal
in many jurisdictions. hackbot enforces a hard safety model:

1. **Scanning is disabled by default.** It requires `enable_scan=true`
   (or `HACKBOT_ENABLE_SCAN=1`).
2. **Allowlist required.** A target is only scanned if it is inside
   `allowed_targets` (an IP or CIDR). Hostnames and out-of-scope targets are
   refused before nmap is ever invoked.
3. **Ingestion is the default mode.** Use `nmap parse`/`analyze`/`pipeline` on
   XML you produced yourself; no scanning happens.

Only scan systems you own or are explicitly authorized to test.

## Configuration

Optional JSON file (`-config hackbot.json`, see `hackbot.example.json`) with
env-var overrides:

| File key | Env var | Default | Notes |
|---|---|---|---|
| `name` | `HACKBOT_NAME` | `hackbot` | display name |
| `interval_seconds` | `HACKBOT_INTERVAL_SECONDS` | `60` | bot loop tick |
| `python_cmd` | `HACKBOT_PYTHON_CMD` | `python` | interpreter for helpers |
| `enable_scan` | `HACKBOT_ENABLE_SCAN` | `false` | master scan switch |
| `allowed_targets` | `HACKBOT_ALLOWED_TARGETS` | _(empty)_ | comma-separated IPs/CIDRs |
| `nmap_path` | `HACKBOT_NMAP_PATH` | `nmap` | nmap binary |
| `nmap_scripts` | `HACKBOT_NMAP_SCRIPTS` | _(safe recon set)_ | comma-separated NSE scripts; `none` disables |
| `llm_base_url` | `HACKBOT_LLM_BASE_URL` | _(empty)_ | OpenAI-compatible base URL |
| `llm_api_key` | `HACKBOT_LLM_API_KEY` | _(empty)_ | LLM auth token |
| `llm_model` | `HACKBOT_LLM_MODEL` | _(empty)_ | model ID |
| `github_repo` | `HACKBOT_GITHUB_REPO` | _(empty)_ | `owner/name` for issues |

## Testing

```bash
go test ./... -race -cover     # Go tests
python -m pytest pythontools   # Python helper tests
```

CI runs both on every push and pull request.

## Status

Early scaffold — core loop, Python escape hatch, and the nmap analysis/agent
pipeline are in place; broader bot features are tracked as issues.

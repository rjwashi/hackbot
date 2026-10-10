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
│   ├── vulscan/            # vulscan (VulDB) NSE output -> findings
│   ├── cve/                # CVE search (NVD) agent
│   └── agent/              # pipeline: analyze -> [LLM] -> [issues]
├── docs/agents.md          # all agents + resource/reporting recommendations
├── pythontools/            # Python helpers (slugify, count_words, ...)
├── .github/workflows/ci.yml  # CI: gofmt, vet, build, test + pytest
└── README.md
```

## Requirements

- [Go](https://go.dev/dl/) 1.27+
- Python 3.11+ (only needed for `hackbot py ...`)
- [nmap](https://nmap.org/download.html) (only needed for `hackbot nmap scan ...`)
- [vulscan](https://github.com/scipag/vulscan) (optional; only for `-vulscan`)

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

# vulscan (VulDB) vulnerability matches from NSE output
hackbot nmap vulscan scan.xml

# GUARDED scan of an allowlisted target, then analyze + recon
hackbot nmap scan    192.168.1.10

# GUARDED scan with vulscan added
hackbot nmap scan    192.168.1.10 -vulscan

# CVE search by category / keyword / detected software
hackbot cve search xss
hackbot cve keyword "redis 7.0"
hackbot cve scan scan.xml

# List every agent
hackbot agents

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

### vulscan recon

[scipag/vulscan](https://github.com/scipag/vulscan) is an NSE script that
matches fingerprinted services against offline VulDB databases and prints
`[id] title` rows. hackbot parses those rows and reports them as **potential**
(not confirmed) findings at `MEDIUM`:

```bash
hackbot nmap vulscan scan.xml          # human summary
hackbot nmap vulscan scan.xml -json    # machine-readable
```

Install vulscan into nmap's scripts dir (documented install) and add it to a
guarded scan with `-vulscan`:

```bash
git clone https://github.com/scipag/vulscan /usr/share/nmap/scripts/vulscan
hackbot nmap scan 192.168.1.10 -vulscan
```

Point at a custom checkout or a single database via config/env:

```bash
HACKBOT_VULSCAN_DIR=/opt/vulscan HACKBOT_VULSCAN_DB=cve.csv \
  hackbot nmap scan 192.168.1.10 -vulscan
```

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

## CVE search (NVD) agent

Search public vulnerability data by category, keyword, or the software nmap
detected. Defaults to the free NIST
[NVD 2.0 API](https://nvd.nist.gov/developers/vulnerabilities) (read-only); no
key is required.

```bash
hackbot cve categories                 # list categories (xss, sqli, rce, ...)
hackbot cve search xss                 # CVEs for a category, worst-first
hackbot cve search rce -limit 10 -min-score 7
hackbot cve keyword "apache 2.4"       # free-text search
hackbot cve scan scan.xml              # CVEs for nmap-detected software
```

Set `nvd_api_key` (`HACKBOT_NVD_API_KEY`) to raise the NVD rate limit from
5 to 50 requests / 30s. `nvd_base_url` overrides the endpoint (mirrors/tests).

See [`docs/agents.md`](docs/agents.md) for the full agent list and
recommendations on gathering richer reports (EPSS, CISA KEV, OSV/GHSA,
CPE-based matching, caching, SARIF/CycloneDX).

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
| `nmap_script_args` | `HACKBOT_NMAP_SCRIPT_ARGS` | _(empty)_ | extra nmap `--script-args` |
| `vulscan_dir` | `HACKBOT_VULSCAN_DIR` | _(empty)_ | vulscan checkout dir |
| `vulscan_db` | `HACKBOT_VULSCAN_DB` | _(empty)_ | vulscan database name |
| `llm_base_url` | `HACKBOT_LLM_BASE_URL` | _(empty)_ | OpenAI-compatible base URL |
| `llm_api_key` | `HACKBOT_LLM_API_KEY` | _(empty)_ | LLM auth token |
| `llm_model` | `HACKBOT_LLM_MODEL` | _(empty)_ | model ID |
| `github_repo` | `HACKBOT_GITHUB_REPO` | _(empty)_ | `owner/name` for issues |
| `nvd_base_url` | `HACKBOT_NVD_BASE_URL` | NVD 2.0 endpoint | CVE API endpoint |
| `nvd_api_key` | `HACKBOT_NVD_API_KEY` | _(empty)_ | raises NVD rate limit |

## Testing

```bash
go test ./... -race -cover     # Go tests
python -m pytest pythontools   # Python helper tests
```

CI runs both on every push and pull request.

## Status

Early scaffold — core loop, Python escape hatch, the nmap analysis/agent
pipeline (analyze + NSE recon + vulscan), and a CVE search (NVD) agent are in
place; broader bot features are tracked as issues. See `docs/agents.md`.

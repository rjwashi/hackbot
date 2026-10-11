# hackbot

A Go-first security toolkit with Python helpers, by [@rjwashi](https://github.com/rjwashi).

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

Run `hackbot py --help` for all available helpers.

## Agents

hackbot ships 44 composable security **agents**. Run `hackbot agents` to print the full catalog, or see [`docs/agents.md`](docs/agents.md) for details.

### Web Security Testing (WSTG)

Twelve agents cover the OWASP WSTG, one per checklist under `src/agent_files/`:

```bash
hackbot web list                 # all 12 categories
hackbot web show injection       # one checklist (slug, code, or name)
hackbot web tools injection      # free tool catalog for one category
hackbot web plan injection       # test -> tool mapping
hackbot web run injection 10.0.0.1 -test WSTG-INJT-05   # guarded, dry-run default
```

## Recon / OSINT agent (`recon`)

Free recon tools against an allowlisted domain or host:

```bash
hackbot recon list               # the tasks (subdomains, dns, ports, ...)
hackbot recon chains             # the pipelines (currently: footprint)
hackbot recon tools              # free tool catalog (subfinder, dnsx, naabu, ...)
hackbot recon tools subdomains   # alternates for one task
hackbot recon plan               # every task and the exact command it runs
hackbot recon subdomains example.com   # guarded (dry-run by default)
hackbot recon footprint example.com    # chain: subdomains -> live HTTP
```

Tasks: `subdomains` (subfinder), `dns` (dnsx), `ports` (naabu), `services`
(nmap), `http` (httpx), `whois`, `urls` (gau).

Chains pipe one task's stdout into the next (no shell). `recon footprint` runs subfinder → httpx.

## Content discovery agent (`discover`)

Content discovery with ffuf/gobuster (wordlist defaults to SecLists `common.txt`):

```bash
hackbot discover list
hackbot discover tools
hackbot discover plan
hackbot discover dirs example.com         # guarded (dry-run by default)
hackbot discover vhosts 10.0.0.5 -wordlist /path/to/list.txt
```

Tasks: `dirs`, `files`, `extensions`, `vhosts`, `params`. Same guarded runner as recon.

## Secret-scanning agent (`secrets`)

Scans a **local path** for leaked credentials (gated by `allowed_paths`):

```bash
hackbot secrets list
hackbot secrets tools
hackbot secrets plan
hackbot secrets scan .            # working tree (gitleaks); guarded, dry-run default
hackbot secrets history .         # full git history (gitleaks)
hackbot secrets verify .          # only live-verified findings (trufflehog)
hackbot secrets entropy .         # entropy/pattern baseline (detect-secrets)
```

Tasks: `scan`/`history` (gitleaks), `verify` (trufflehog), `entropy` (detect-secrets).

## Dependency / SBOM agent (`deps`)

SBOM and vulnerability report for a local project (gated by `allowed_paths`):

```bash
hackbot deps list
hackbot deps tools
hackbot deps plan
hackbot deps vulns .              # dependency + OS CVE scan (trivy)
hackbot deps sbom .               # CycloneDX SBOM (syft)
hackbot deps grype .              # alternate DB match (grype)
hackbot deps osv .                # OSV database scan (osv-scanner)
```

Tasks: `vulns` (trivy), `sbom` (syft), `grype`, `osv` (osv-scanner).

## nmap agent

Ingest nmap results and run a modular analysis pipeline:

```
parse -> rule-based risk report -> [LLM explanation] -> [GitHub issues]
```

### Commands

```bash
hackbot nmap parse   scan.xml          # list hosts/ports
hackbot nmap analyze scan.xml          # rule-based risk report
hackbot nmap recon   scan.xml          # NSE script output
hackbot nmap vulscan scan.xml          # VulDB matches
hackbot nmap scan    192.168.1.10     # guarded scan
hackbot nmap scan    192.168.1.10 -vulscan
hackbot nmap pipeline scan.xml -llm -issues -repo rjwashi/hackbot -min-severity high
hackbot cve search xss                 # CVE by category
hackbot cve keyword "redis 7.0"        # CVE by keyword
hackbot cve scan scan.xml              # CVE for nmap-detected software
hackbot agents                         # list all agents
hackbot web list                       # WSTG checklists
hackbot web show injection              # one checklist
```

Produce the XML input with nmap yourself:

```bash
nmap -sV -oX scan.xml 192.168.1.0/24
```

### Risk rules

Flags risky services (Docker API, Redis, MongoDB, SMB, RDP, etc.) as `MEDIUM`/`HIGH`; other ports as `INFO`.

### NSE recon

Parses NSE output from XML. Default profile: `banner`, `http-title`, `http-headers`, `ssh-hostkey`, `ssl-cert`.

```bash
hackbot nmap recon scan.xml          # list script results
hackbot nmap recon scan.xml -json    # machine-readable
hackbot nmap scan 192.168.1.10 -scripts safe,default   # override profile
hackbot nmap scan 192.168.1.10 -scripts none           # ports/services only
```

### vulscan recon

Parses vulscan NSE output as **potential** `MEDIUM` findings:

```bash
hackbot nmap vulscan scan.xml          # human summary
hackbot nmap vulscan scan.xml -json    # machine-readable
hackbot nmap scan 192.168.1.10 -vulscan                              # default checkout
HACKBOT_VULSCAN_DIR=/opt/vulscan hackbot nmap scan 192.168.1.10 -vulscan  # custom
```

### LLM stage

Set an OpenAI-compatible endpoint; `-llm` prioritizes findings and suggests remediation. Skipped if not configured.

### Actions stage

`-issues` files GitHub issues per finding (≥ `-min-severity`, capped at `-max-issues`). Dry-run by default; `-dry-run=false` to create via `gh`.

## CVE search (NVD) agent

Search NIST NVD 2.0 API (read-only, key-free) by category, keyword, or nmap-detected software:

```bash
hackbot cve categories                 # list categories (xss, sqli, rce, ...)
hackbot cve search xss                 # CVEs for a category, worst-first
hackbot cve search rce -limit 10 -min-score 7
hackbot cve keyword "apache 2.4"       # free-text search
hackbot cve scan scan.xml              # CVEs for nmap-detected software
```

`nvd_api_key` raises the rate limit (5 → 50 req/30s). `nvd_base_url` overrides the endpoint.

See [`docs/agents.md`](docs/agents.md) for the full catalog and enrichment recommendations (EPSS, KEV, OSV/GHSA, CPE, SARIF).

## ⚠️ Authorized use only

**Authorized use only.** hackbot enforces:

1. **Scanning disabled by default** — requires `enable_scan=true`.
2. **Allowlist required** — `allowed_targets` (IP/CIDR), `allowed_domains` (names), or `allowed_paths` (local dirs for `secrets`/`deps`).
3. **Dry-run by default** — `web run`, `recon *`, `discover *`, `secrets *`, `deps *`, and issue creation send nothing until `-dry-run=false`.
4. **Ingestion is the default mode** — `nmap parse`/`analyze`/`pipeline` on XML you produced yourself; no scanning happens.

## Configuration

Optional JSON config (`-config hackbot.json`), env vars override:

| File key | Env var | Default |
|---|---|---|
| `name` | `HACKBOT_NAME` | `hackbot` |
| `interval_seconds` | `HACKBOT_INTERVAL_SECONDS` | `60` |
| `python_cmd` | `HACKBOT_PYTHON_CMD` | `python` |
| `enable_scan` | `HACKBOT_ENABLE_SCAN` | `false` |
| `allowed_targets` | `HACKBOT_ALLOWED_TARGETS` | _(empty)_ |
| `allowed_domains` | `HACKBOT_ALLOWED_DOMAINS` | _(empty)_ |
| `allowed_paths` | `HACKBOT_ALLOWED_PATHS` | _(empty)_ |
| `wordlist` | `HACKBOT_WORDLIST` | SecLists `common.txt` |
| `nmap_path` | `HACKBOT_NMAP_PATH` | `nmap` |
| `nmap_scripts` | `HACKBOT_NMAP_SCRIPTS` | _(safe recon set)_ |
| `nmap_script_args` | `HACKBOT_NMAP_SCRIPT_ARGS` | _(empty)_ |
| `vulscan_dir` | `HACKBOT_VULSCAN_DIR` | _(empty)_ |
| `vulscan_db` | `HACKBOT_VULSCAN_DB` | _(empty)_ |
| `llm_base_url` | `HACKBOT_LLM_BASE_URL` | _(empty)_ |
| `llm_api_key` | `HACKBOT_LLM_API_KEY` | _(empty)_ |
| `llm_model` | `HACKBOT_LLM_MODEL` | _(empty)_ |
| `github_repo` | `HACKBOT_GITHUB_REPO` | _(empty)_ |
| `nvd_base_url` | `HACKBOT_NVD_BASE_URL` | NVD 2.0 endpoint |
| `nvd_api_key` | `HACKBOT_NVD_API_KEY` | _(empty)_ |

## Testing

```bash
go test ./... -race -cover     # Go tests
python -m pytest pythontools   # Python helper tests
```

## Status

Core loop, nmap pipeline, CVE (NVD), 12 WSTG agents, recon/discover/secrets/deps agents. See `docs/agents.md` for details.

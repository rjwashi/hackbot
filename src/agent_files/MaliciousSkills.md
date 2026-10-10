| # | Check | Evidence to look for |
|---|-------|---------------------|
| 1.1 | Has the skill been obtained from a verified, trusted source? | Publisher identity confirmed; not a typosquat of a known skill name |
| 1.2 | Has the skill passed behavioral security analysis (not just pattern matching)? | Scan report from a tool that evaluates intent, not only code signatures |
| 1.3 | Has cryptographic signature verification been performed? | Valid ed25519 signature; `content_hash` matches published manifest |
| 1.4 | Have all skill scripts and natural language instructions been reviewed for malicious patterns? | No encoded payloads, no `curl` to unknown endpoints, no credential access beyond stated function in code or natural language instructions |
| 1.5 | Has the skill been tested in an isolated canary environment before production deployment? | Dynamic test report showing observed behavior matches declared behavior |
| 1.6 | Does the skill avoid writing to agent identity files (`SOUL.md`, `MEMORY.md`, `AGENTS.md`)? | No write access to identity files unless explicitly justified and approved *(see also 3.6 — privilege angle)* |

**Motivated by**: ClawHavoc campaign (1,184 malicious skills); 5 of top 7 most-downloaded ClawHub skills at peak infection were confirmed malware.
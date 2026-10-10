| # | Check | Evidence to look for |
|---|-------|---------------------|
| 3.1 | Does the skill declare a permission manifest with explicit, scoped permissions? | Manifest present; permissions enumerated (not open-ended) |
| 3.2 | Are permissions minimized to the skill's stated functionality? | No access beyond what the described function requires |
| 3.3 | Does the skill avoid unrestricted shell access (`shell: true`)? | `shell: false` or shell access scoped to specific commands |
| 3.4 | Are file permissions scoped to specific paths (no `**/*` wildcards)? | Explicit file paths declared; no broad globs |
| 3.5 | Does the skill use per-skill scoped credentials (not shared agent-level API keys)? | Credentials isolated to this skill's scope; rotated on schedule |
| 3.6 | Is write access to agent identity files (`SOUL.md`, `MEMORY.md`) flagged for elevated review? | Write access to identity files requires explicit justification and approval *(see also 1.6 — persistence angle)* |
| 3.7 | Are network permissions declared as domain allowlists (not binary `network: true/false`)? | Specific domains listed; default deny for all other egress |
| 3.8 | Does the skill avoid accessing credential stores, `.env` files, wallet files, or SSH keys beyond its stated function? | No reads to `~/.ssh/`, `~/.aws/`, `.env`, `**/credentials*`, `*.wallet`, or browser data directories unless explicitly required and justified |

**Motivated by**: 280+ ClawHub skills exposing API keys and PII beyond declared function (Snyk, Feb 2026). ClawHavoc campaign specifically targeted `.env` files, exchange API keys, wallet private keys, SSH credentials, and browser passwords. OpenClaw default grants full shell, file, network, and cron access.

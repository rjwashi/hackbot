| # | Check | Evidence to look for |
|---|-------|---------------------|
| 4.1 | Does the skill description accurately and completely reflect its actual functionality? | No hidden capabilities; description matches observed behavior |
| 4.2 | Has metadata been scanned for ASCII smuggling, zero-width Unicode, and base64-encoded payloads? | Clean scan; no steganographic content in `SKILL.md` natural language instructions or manifest |
| 4.3 | Are default metadata configurations secure (not permissive)? | No default-open permissions; dangerous capabilities (shell, network, identity file writes) require explicit opt-in in the manifest |
| 4.4 | Has metadata been validated against a security schema? | Schema validation passed; no unexpected or undeclared fields |
| 4.5 | Is the declared `risk_tier` consistent with the actual permission scope? | Cross-reference: a skill declaring `L0` (safe) with `shell: true` is a red flag |
| 4.6 | Has brand/trademark impersonation been checked? | Skill name does not impersonate a known brand without affiliation |
| 4.7 | Are all YAML files parsed with safe loaders (`yaml.safe_load`, not `yaml.load`)? | No unsafe YAML tags (`!!python/object`, `!!python/apply`) in skill files |
| 4.8 | Are skill config files parsed and validated in an isolated subprocess or container before execution? | Deserialization happens in sandboxed context with no access to host resources |
| 4.9 | Is an allowlist of permitted YAML/JSON keys enforced? | Unexpected or undeclared fields are rejected |
| 4.10 | Are `requirements.txt`, `package.json`, and `pyproject.toml` within skill packages treated as untrusted code? | Dependency installation sandboxed; not executed with agent privileges |
| 4.11 | Has schema validation (JSON Schema, Pydantic, or equivalent) been applied before any deserialization of skill-provided data? | Validation step confirmed in skill loader pipeline |
| 4.12 | Is deserialization performed with minimum privileges (not elevated agent context)? | Privilege drop confirmed before parsing |

**Motivated by**: Malicious "Google," "Solana Wallet Tracker," and "Polymarket Trader" skills on ClawHub — none affiliated with named brands. ASCII smuggling confirmed in Snyk's toxicskills-goof samples. PyYAML `!!python/object` allows arbitrary code execution on load; ClawHavoc staged downloads triggered a secondary payload during the dependency-install phase.
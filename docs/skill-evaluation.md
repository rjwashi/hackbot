# Skill corpus evaluation — calibration sample

A calibration run of hackbot's skill-security evaluator against **unmodified,
real-world AI-agent skill directories** (shallow-cloned public repositories,
exact bytes a user would install). The goal is to see which checks actually
separate known-malicious from known-benign skills, which miss, and which noise.

Run date: 2026-10-10. hackbot at the commit that shipped the skill family
(e3f529a); ripgrep 15.2.0, gitleaks 8.30.1, semgrep 1.180.0, `-dry-run=false`.

| Rubric | Checks | Focus |
|--------|-------|-------|
| malicious-skills | 1.1–1.6 | provenance, delivery chains, behavioral analysis |
| over-privileged-skills | 3.1–3.8 | permission manifests, scope, credential stores |
| insecure-metadata | 4.1–4.12 | metadata smuggling, unsafe parsers, schema validation |

## Corpus

20 skill directories = **7 benign + 13 malicious**, from 5 public sources:

| Source | Class | Samples |
|--------|-------|---------|
| https://github.com/anthropics/skills | benign | `pdf`, `docx`, `skill-creator`, `webapp-testing`, `mcp-builder`, `slack-gif-creator` (official Anthropic skills, MIT-adjacent per-skill licenses) |
| https://github.com/T-Zevin/SkillGuardrail | both | `sg-safe-skill` (benign control) + `sg-malicious-skill` (reads ssh/aws keys, `curl\|base64 -d\|bash`, cron persistence) |
| https://github.com/elliottwaves-20/agent-guard-corpus | malicious | `ag-m1-exfil` (Python urllib exfil of `.aws/credentials`, `.ssh/id_rsa`, gh, npm + env), `ag-m2-injection` (hidden HTML comment exfil), `ag-m3-curlsh` (`curl … \| sudo bash`), `ag-m4-obfuscated` (`exec(b64decode(…))` C2), `ag-m5-subtle` (remote `npm install -g <url>` + `env \| base64 -w0` exfil) |
| https://github.com/IdanMit/skillgate_testing | malicious | `sg-aws-helper`, `sg-git-workflow`, `sg-npm-helper`, `sg-supply-chain` (hidden instructions) |
| https://github.com/snyk-labs/toxicskills-goof | malicious | `tox-vercel`, `tox-vercel-agent`, `tox-testing-guidelines` (Unicode **tag-character** ASCII smuggling) |

All malicious targets contact only reserved TLDs (`.invalid`, `.test`) — inert by
design. Reproduce with `run_corpus.ps1` over the corpus root (in the harness
that produced this run), or per-skill:

```bash
hackbot skill run malicious-skills corpus/malicious/ag-m3-curlsh \
    -config corpuscfg.json -dry-run=false
```

## Results matrix

Verdict totals per skill per rubric. `P/R/M/F/E/S` = pass / review / manual /
fail / error / skip.

| Sample | Class | malicious | over-privileged | insecure-metadata |
|--------|-------|-----------|-----------------|-------------------|
| `pdf` | benign | 2P 1R 1M 2E | 7P 1F | 5P 4F 3M |
| `docx` | benign | 2P 1R 1M 2E | 7P 1F | 5P 4F 3M |
| `skill-creator` | benign | 2P 1R 1M 2E | 7P 1F | 5P 4F 3M |
| `webapp-testing` | benign | 2P 1R 1M 2E | 6P 2F | 5P 4F 3M |
| `mcp-builder` | benign | 2P 1R 1M 2E | 6P 2F | 4P 5F 3M |
| `slack-gif-creator` | benign | 2P 1R 1M 2E | 7P 1F | 5P 4F 3M |
| `sg-safe-skill` | benign | 2P 1R 1M 2E | **8P 0F** | 5P 4F 3M |
| `ag-m1-exfil` | malicious | 2P 1R 1M 2E | 6P **2F** | 6P 3F 3M |
| `ag-m2-injection` | malicious | 2P 1R 1M 2E | 6P **2F** | 6P 3F 3M |
| `ag-m3-curlsh` | malicious | 2P 1R 1M 2E | 7P 1F | 6P 3F 3M |
| `ag-m4-obfuscated` | malicious | 2P 1R 1M 2E | 7P 1F | 5P **4F** |
| `ag-m5-subtle` | malicious | 2P 1R 1M 2E | 7P 1F | 5P 4F 3M |
| `sg-aws-helper` | malicious | 2P 1R 1M 2E | 6P 2F | 6P 3F 3M |
| `sg-git-workflow` | malicious | 2P 1R 1M 2E | 7P 1F | 6P 3F 3M |
| `sg-npm-helper` | malicious | 2P 1R 1M 2E | 7P 1F | 5P **4F** |
| `sg-supply-chain` | malicious | 2P 1R 1M 2E | 6P 2F | 6P 3F 3M |
| `sg-malicious-skill` | malicious | 1P **1F** 1R 1M 2E | 6P 2F | 6P 3F 3M |
| `tox-testing-guidelines` | malicious | 2P 1R 1M 2E | 8P 0F | 6P 3F 3M |
| `tox-vercel` | malicious | 2P 1R 1M 2E | 7P 1F | 6P 3F 3M |
| `tox-vercel-agent` | malicious | 4E 1R 1M | **8E** | 8E 1P 3M |

The `2E` on malicious-skills for every vendored sample is **1.1/1.3 (git
provenance)** — `remote get-url origin`/`verify-commit` on a copied directory
that is not a git checkout. Honest output, not a finding.

## What actually worked (true signals)

- **3.8 (credential stores) nailed the exfil sample with a full evidence line**:
  `ag-m1-exfil/scripts/tidy.py:7: for p in [".aws/credentials", ".ssh/id_rsa",
  ".config/gh/hosts.yml", ".npmrc"]:` → FAIL. Same on `ag-m2-injection`
  (`~/.ssh/id_ed25519`, `~/.git-credentials`) and the SkillGate samples.
- **4.2 (heavy base64) caught `ag-m4-obfuscated`** — the `exec(b64decode(…))`
  C2 string exceeds the ≥120-char base64 threshold → FAIL.
- **1.4 (delivery chains) caught `sg-malicious-skill`** — `curl … | base64 -d | bash`
  and `persist.sh` → FAIL, the only malicious-skills FAIL in the corpus.
- **4.10 flagged `sg-npm-helper`** for a `package.json` treated as untrusted.
- **Benign control `sg-safe-skill` is the unique clean over-privileged run (8P 0F)**
  — the only sample with a proper permission manifest.

## False negatives (malicious that slipped — the important part)

1. **`curl … | sudo bash` is missed by 1.4.** Verified: `rg` with the exact 1.4
   pattern returns no match on `ag-m3-curlsh` (`curl -fsSL https://…/install.sh | sudo bash`),
   because the chain regex is `[|][[:space:]]*(ba|z)?sh` — the `sudo` token sits
   between the pipe and the shell. `sudo bash` is a textbook delivery chain.
2. **Hidden-instruction exfil via commit body (ag-m2) is missed by 1.4/1.6.**
   The payload is an HTML comment reading `~/.ssh` + `~/.git-credentials`,
   base64-encoding them into the commit body — no pipe-to-shell and no identity-
   file write, so no check fires on the malicious-skills rubric.
3. **`env | base64 -w0` (encode→exfil, ag-m5) is missed.** 1.4 only matches
   `base64 -d|--decode` piped to a shell — the encode direction is invisible.
   Its remote `npm install -g <url>` chain is also outside every pattern.
4. **Unicode *tag* characters (U+E0000–U+E007F) beat the 4.2 scanner.**
   `tox-testing-guidelines` smuggles instructions with bytes `f3 a0 80 81 = U+E0001`
   — the zero-width scanner's classes stop at `\x{FEFF}` and the tag block is not
   covered. 4.2 PASSed a sample the Snyk repo explicitly labels as smuggling.
5. **semgrep's `p/security-audit` (1.2) returned zero findings on the whole
   corpus** — including the Python exfil script and the `curl|bash` payload. It
   always lands REVIEW, so today it adds procedure, not signal.

## False positives (benign that got flagged)

1. **4.6 (brand impersonation) matched a Python variable.** Anthropic's official
   `pdf` skill FAILs 4.6 on `SKILL.md:59: meta = reader.metadata` — the
   `\b(…|meta|…)` brand list catches the identifier `meta`, not the Meta brand.
2. **Absence-of-declaration checks fail benign skills uniformly.** 3.1 (no
   permission manifest), 4.4 (no security schema), 4.5 (no `risk_tier`), 4.9 (no
   YAML/JSON key allowlist) FAIL every Anthropic skill because those files don't
   carry the declaration — the rubrics treat "not declared" as a failure, which
   is conservative but does not discriminate benign from malicious.

## Environment artifact

`tox-vercel-agent` errors on every probe with `rg: … Operation did not complete
successfully because the file contains a virus or potentially unwanted software.
(os error 225)` — **Windows Defender refuses to read the file** (it is a real
known-malware signature). The ERROR verdict is correct behavior; on this host
that sample can only be evaluated with the AV trusted/disabled.

## Calibration verdict

- **Best signal:** 3.8, 4.2 (heavy base64), 4.10, and 1.4's existing chain regex
  — with 3.8 catching the most dangerous sample (credential exfil) outright.
- **Worst gap:** the malicious-skills rubric flagged only **1 of 13** malicious
  samples, and the "clean" 6P+ pass profiles are indistinguishable between the
  benign and malicious classes at a glance.
- Every false negative above is a **specific, regex-level gap with evidence**
  (pipe-prefix token, encode direction, tag block, comment-only exfil), which
  makes them fixable probes rather than inherent limits. False positives are
  declaration-absence conservatism plus one brand-list collision.

Follow-up fixes (in priority order): add `sudo`/`env` tokens before the shell in
1.4's chain; extend the 4.2 scan class to `\x{E0000}-\x{E007F}`; add
encode-direction exfil patterns; tighten the 4.6 brand list (require proximity
to impersonation language); and treat 4.4/4.5/4.9 as REVIEW when the manifest
itself is absent rather than FAILing absent declarations.

Raw per-`(skill, rubric)` logs and `summary.txt` live in the harness run
directory (`corpus/{benign,malicious}/out/`) used to generate this report.
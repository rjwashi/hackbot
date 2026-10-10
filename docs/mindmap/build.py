#!/usr/bin/env python3
"""Regenerate the hackbot concept maps (v2-overview.cxl + v2-overview.txt).

WHY a generator at all: a CmapTools .cxl file and its plain-text mirror must say
the same thing, and hand-keeping two encodings of ~60 concepts in sync is exactly
the drift bug our Go drift-tests ("TestAgentsDocsInSync") exist to prevent. Here
one in-code structure (CONCEPTS + EDGES) is the single source, and both files are
emitted from it, so they cannot diverge.

WHY not hand-write the XML: a single wrong id reference makes CmapTools silently
drop an edge. Generating ids (c1.., l1..) and every appearance entry guarantees
referential integrity and a valid document.

Trade-off / alternative: we could store the map as JSON and render CXL on demand,
but CmapTools' .cxl *is* the map of record (the README says so), so we emit it
directly. If you edit the map in CmapTools, port those edits back into CONCEPTS
below and re-run this script so the two stay authoritative together.

Usage:  python docs/mindmap/build.py
"""

from __future__ import annotations

import html  # escape &, <, >, " for XML attribute/text safety
from collections import defaultdict, deque  # tree walk + BFS depth for layout
from pathlib import Path  # resolve output paths next to this script

# ---------------------------------------------------------------------------
# CONTENT (the single source of truth).
#
# Each concept is (key, label, comment). The comment becomes a CmapTools
# long-comment: its job is to explain WHY the concept exists and what
# alternatives were rejected, so a newcomer understands the map without the code.
# ---------------------------------------------------------------------------
CONCEPTS: list[tuple[str, str, str]] = [
    (
        "root",
        "hackbot",
        "Root concept. hackbot is a Go-first security toolkit with a small Python "
        "escape hatch. It wraps free/open-source tools behind one CLI, treats each "
        "capability as an 'agent', and forces every active action through a two-gate "
        "safety model (enable + allowlist). This is map v2: it reflects the five "
        "shipped agent families (nmap, cve, web/WSTG, recon, discover) and the shared "
        "engine that backs the last two.",
    ),
    # ----- IDENTITY -------------------------------------------------------
    (
        "identity",
        "WHAT IT IS",
        "The one-paragraph answer to 'what is this?' before any detail. Keep this "
        "section short; the rest of the map only makes sense once this is clear.",
    ),
    (
        "go_first",
        "a Go-first security toolkit with a Python escape hatch",
        "Go is the core because it produces a single static binary, cross-compiles "
        "cleanly, and its stdlib covers HTTP/XML/JSON (the formats every agent "
        "speaks). Python is reserved for the few helpers Go can't do tidily "
        "(desktop glue), reached via 'hackbot py'. Alternative rejected: a pure "
        "Python tool is faster to prototype but harder to ship and test everywhere.",
    ),
    (
        "repo",
        "github.com/rjwashi/hackbot (public, main)",
        "The repo is public on purpose: the safety model should be auditable, not "
        "hidden. Docs, the agent registry, and the tool catalogs are kept honest by "
        "drift tests rather than by discipline.",
    ),
    (
        "binary",
        "one binary: bin/hackbot.exe (go build -o bin/hackbot.exe .)",
        "One binary with many subcommands keeps distribution trivial. Build locally "
        "with the command shown; CI also builds and runs tests (the -race run needs "
        "cgo, so it runs on the ubuntu runner, not on a bare Windows box).",
    ),
    # ----- PURPOSE --------------------------------------------------------
    (
        "purpose",
        "PURPOSE",
        "The north star. Every new agent is judged against these three lines.",
    ),
    (
        "why_findings",
        "turn scans and checklists into prioritized, actionable findings",
        "The product is a ranked, human-readable report, not raw tool noise. "
        "internal/nmap does this with rule-based analysis; internal/wstg does it by "
        "mapping each checklist test to a tool. Alternative rejected: dumping raw "
        "tool output is easier to build but shifts all the work to the reader.",
    ),
    (
        "why_free",
        "use only free / open-source tools",
        "Anyone must be able to reproduce a run, so every catalog entry carries a "
        "license and an install hint. This is a hard rule enforced by catalog tests "
        "(every tool must declare a license and URL). Alternative rejected: paid "
        "feeds (Vulners etc.) are higher fidelity but not reproducible by users.",
    ),
    (
        "why_authorized",
        "never touch a system that is not explicitly authorized",
        "Security tooling is dual-use. The whole safety model exists so hackbot "
        "cannot be aimed at arbitrary targets 'by accident'. This is the single "
        "most important design constraint and the reason several features are "
        "deliberately manual.",
    ),
    # ----- AGENT FAMILIES -------------------------------------------------
    (
        "families",
        "AGENT FAMILIES",
        "hackbot is built from composable agents grouped into families. The registry "
        "in main.go is the single source of truth; 'hackbot agents' prints it and "
        "tests keep docs/agents.md and the README snapshot in sync.",
    ),
    (
        "fam_nmap",
        "nmap family (parse, analyze, recon, vulscan, pipeline, guarded scan)",
        "The original family. It ingests nmap XML, produces a rule-based risk "
        "report, surfaces NSE recon and vulscan matches, and can run a guarded live "
        "scan. Ingest-first is the default mode so no traffic is sent unless asked.",
    ),
    (
        "fam_cve",
        "cve family (categories, search, keyword, scan)",
        "Searches the free NIST NVD 2.0 API by category (pinned to CWEs), by free "
        "text, or by the software nmap fingerprinted. Read-only and key-free; an "
        "optional API key just raises the rate limit (5 -> 50 req/30s).",
    ),
    (
        "fam_web",
        "web (WSTG) family (list, show, tools, plan, run)",
        "Twelve agents, one per OWASP Web Security Testing Guide checklist under "
        "src/agent_files/. The checklist is the agent's capability list; a curated "
        "layer maps each test to a free tool, and the automatable ones can run under "
        "guard. Non-automatable tests deliberately stay manual guidance.",
    ),
    (
        "fam_recon",
        "recon family (subdomains, dns, ports, services, http, whois, urls)",
        "OSINT reconnaissance via subfinder, dnsx, naabu, nmap, httpx, whois, gau. "
        "It operates on DOMAIN NAMES, which the IP/CIDR allowlist deliberately "
        "refuses, which is exactly why the domain allowlist (allowed_domains) exists.",
    ),
    (
        "fam_discover",
        "discover family (dirs, files, extensions, vhosts, params)",
        "Content discovery via ffuf and gobuster. Brute forcing is noisy by nature, "
        "so every task is guarded and dry-run by default, and it borrows a wordlist "
        "from config (defaulting to the free SecLists common list).",
    ),
    (
        "fam_planned",
        "[planned] secrets, deps/SBOM, and cloud families",
        "internal/ops generalizes the 'catalog + guarded runner' pattern, so a new "
        "family is mostly a catalog file plus registry entries. Secrets "
        "(gitleaks/trufflehog) and dependency/SBOM (trivy/grype/osv-scanner) are the "
        "next planned families.",
    ),
    # ----- CLI ------------------------------------------------------------
    (
        "cli",
        "CLI SURFACE",
        "One binary, one verb per capability. Flags may appear anywhere on the line "
        "(a small reorder pass works around Go's flag-before-positional rule, a "
        "recurring usability papercut).",
    ),
    (
        "cli_core",
        "hello · run · version · help · py",
        "Scaffolding commands. 'run' is the bot-loop scaffold; 'py' is the Go->Python "
        "escape hatch used only where Go can't do the job.",
    ),
    (
        "cli_meta",
        "agents · layout",
        "'agents' renders the registry (text/markdown/json/skill); 'layout' prints "
        "the repo tree. Both feed generated docs, so drift tests fail if the docs "
        "aren't regenerated after a change.",
    ),
    (
        "cli_nmap",
        "nmap parse · analyze · recon · vulscan · scan · pipeline",
        "Ingestion verbs (parse/analyze/recon/vulscan/pipeline) never scan; only "
        "'scan' sends traffic and it is guarded.",
    ),
    (
        "cli_cve",
        "cve categories · search · keyword · scan",
        "Read-only NVD queries; no network scanning at all.",
    ),
    (
        "cli_web",
        "web list · show · tools · plan · run",
        "'list/show' are pure reference; 'tools/plan' show the free-tool mapping; "
        "'run' is the guarded executor (dry-run by default).",
    ),
    (
        "cli_recon",
        "recon list · tools · plan · <task> <target>",
        "Same shape as web: list/tools/plan are reference; the bare '<task> <target>' "
        "form is the common case and stays guarded.",
    ),
    (
        "cli_discover",
        "discover list · tools · plan · <task> <target>",
        "Identical shape to recon, backed by the same engine, so muscle memory "
        "carries between families.",
    ),
    # ----- CODE MAP -------------------------------------------------------
    (
        "code",
        "CODE MAP (internal/)",
        "Small, single-purpose packages. Each owns one concern and exposes a narrow "
        "surface; main.go is the only place that composes them.",
    ),
    ("pkg_config", "config/", "JSON file + HACKBOT_* env overrides -> Config struct. Env wins so deployments can override without editing files."),
    ("pkg_bot", "bot/", "The core bot loop (greet/tick/done) and the RunPython bridge; the scaffold future scheduling will hang off."),
    ("pkg_nmap", "nmap/", "nmap XML parsing plus the rule-based Analyze() producing []Finding (ranked worst-first)."),
    ("pkg_scan", "scan/ (+ scope.go)", "The guarded process runner (CommandRunner seam) and the scope checks: InScope (IP/CIDR), DomainInScope (names), PathInScope (future local scans)."),
    ("pkg_agent", "agent/", "The nmap pipeline: analyze -> [LLM narrative] -> [GitHub issues]; owns the Report type."),
    ("pkg_cve", "cve/", "NVD 2.0 client behind a one-method Searcher interface, so extra sources (OSV, GHSA) can drop in later."),
    ("pkg_vulscan", "vulscan/", "Parses vulscan (VulDB) NSE output into potential CVE matches; conservative on purpose (offline data, unconfirmed)."),
    ("pkg_wstg", "wstg/ (+ capability.go, run.go)", "Parses/embeds the WSTG checklists, holds the free-tool catalog and curated checks, and runs them under guard."),
    ("pkg_ops", "ops/ (+ runner.go, recon.go, discovery.go)", "The general capability engine: Tool/Task/Catalog + a guarded Runner. recon and discover are just catalogs on top; future families reuse it."),
    # ----- DATA FLOW ------------------------------------------------------
    ("dataflow", "DATA FLOW", "How data becomes findings. '→' marks transformation; [ ] marks optional stages."),
    ("flow_nmap", "nmap XML (or guarded scan) → parse → analyze → []Finding", "Either you produce the XML yourself, or hackbot runs a guarded scan; both funnel into the same parser so downstream stages don't care about the source."),
    ("flow_llm", "[]Finding → [LLM narrative] → [GitHub issues, dry-run]", "The optional LLM turns ranked findings into prose; issue filing is dry-run until explicitly enabled with -dry-run=false."),
    ("flow_wstg", "WSTG checklist → capability (test→tool) → plan / guarded run", "The checklist supplies the tests; the capability layer supplies the commands; the runner supplies the safety."),
    ("flow_recon", "domain → recon task → tool stdout", "e.g. subfinder -d <domain> -> lines of subdomains. Output is evidence, not a verdict."),
    ("flow_discover", "URL → discovery task → ffuf/gobuster stdout", "e.g. ffuf -u <url>/FUZZ -> discovered paths. Noisy by nature, hence guarded."),
    # ----- SAFETY ---------------------------------------------------------
    ("safety", "SAFETY MODEL", "The rules that make a dual-use tool safe to ship. Every family must obey all of them."),
    ("safe_off", "execution is DISABLED by default (enable_scan)", "Nothing runs (network or local) until enable_scan / HACKBOT_ENABLE_SCAN is set. Alternative rejected: 'read-only is always safe' is false once a tool can clone remote repos."),
    ("safe_allowlist", "an allowlist is REQUIRED (allowed_targets IP/CIDR; allowed_domains names)", "A target must be inside the relevant allowlist before a real run. IPs and domains are separate lists because allowing a CIDR is not consent to hit every domain that resolves into it."),
    ("safe_dry", "actions are DRY-RUN by default (web run, recon, discover, issues)", "The default is to render the exact command and send nothing. You opt in with -dry-run=false. This makes the safe path also the informative path."),
    ("safe_ingest", "ingestion is the default mode", "parse/analyze/recon/vulscan/pipeline and all web/plan commands read data and never scan, so the tool is useful with zero scanning enabled."),
    ("safe_templates", "fixed argument templates (targets are never shell-interpolated)", "Commands are stored as argv arrays with placeholders; the target becomes one argv element, never a shell fragment. This removes an entire class of injection bugs."),
    ("safe_runner", "the runner is the authoritative gate", "The CLI pre-checks for a friendly message, but the runner re-checks enable + scope itself, so a new caller cannot bypass the guards by forgetting them."),
    # ----- CONFIG ---------------------------------------------------------
    ("configsec", "CONFIGURATION", "One optional JSON file, overridable by environment. Env wins so CI/hosted runs need no file."),
    ("cfg_file", "-config hackbot.json (see hackbot.example.json)", "The example file documents every key; absent file means defaults (scanning off)."),
    ("cfg_env", "HACKBOT_* env vars override the file", "Same values, deployable without shipping a file. Truthy parsing accepts 1/true/yes/on."),
    ("cfg_new", "allowed_domains and wordlist (recon/discover)", "allowed_domains gates name-based recon; wordlist feeds content discovery (defaults to the free SecLists common list)."),
    # ----- QUALITY --------------------------------------------------------
    ("quality", "QUALITY", "How correctness is protected as the project grows."),
    ("q_go", "Go tests per package (table-driven)", "Each package carries focused tests; the safety-critical paths (scope, runner gates) are tested with fakes so they run with no network and no tools installed."),
    ("q_py", "Python tests (pytest over pythontools/)", "The escape-hatch helpers are tested too, since they run in the same product."),
    ("q_ci", "CI: gofmt + vet + build + test -race + pytest", "Formatting, vetting, race testing, and the Python suite all gate every push/PR."),
    ("q_drift", "drift tests keep registry, docs, and catalogs in sync", "Adding a checklist/agent without updating docs fails the build. This is why the generated tables in the README and docs never rot."),
    # ----- ROADMAP --------------------------------------------------------
    ("roadmap", "ROADMAP", "Planned next steps. '[ ]' marks not-done; these mirror the recommendations in docs/agents.md."),
    ("rm_secrets", "[ ] secrets scanning (gitleaks, trufflehog)", "Local/repo secret detection. Reuses the ops engine with a path target kind; read-only."),
    ("rm_deps", "[ ] dependency / SBOM (trivy, grype, osv-scanner)", "SCA over a project directory; produces CycloneDX and prioritized vulns. Reuses ops."),
    ("rm_cloud", "[ ] cloud posture (prowler)", "Cloud account auditing. Needs a cloud-account allowlist and credentials, so it gets its own careful gate."),
    ("rm_chain", "[ ] recon → discover chaining", "Feed recon output (subdomains, live hosts) into discovery so one allowlisted seed expands into a full footprint."),
    ("rm_skills", "[ ] generate OpenCode skills from agents", "Each registry entry is already skill-shaped; 'hackbot agents -format skill' scaffolds them."),
    ("rm_enrich", "[ ] vulscan → NVD enrichment; EPSS/KEV; SARIF/CycloneDX", "Attach CVSS/EPSS/KEV to vulscan CVEs, rank by exploitation likelihood, and export CI-friendly formats."),
    # ----- META -----------------------------------------------------------
    ("meta", "MIND MAP META", "How to read and maintain this map."),
    ("meta_cxl", "CXL (CmapTools) is the map of record; .txt mirrors it", "Edges are propositions: concept -> linking phrase -> concept. Open the .cxl in CmapTools (File -> Open)."),
    ("meta_comments", "long-comments explain the 'why' and the rejected alternatives", "Most concepts carry a long-comment explaining the reasoning, not just the label, so the map teaches the design."),
    ("meta_versions", "one version per milestone; older versions stay for history", "v1 captured the nmap milestone; v2 captures the five-family project; a future final-annotated pass can expand every concept for a newcomer."),
]

# Edges form a TREE rooted at 'root' so the .txt outline is a faithful mirror of
# the .cxl. Each edge is (parent_key, linking_phrase, child_key).
EDGES: list[tuple[str, str, str]] = [
    ("root", "is", "identity"),
    ("identity", "is", "go_first"),
    ("identity", "lives at", "repo"),
    ("identity", "builds to", "binary"),

    ("root", "exists to", "purpose"),
    ("purpose", "produces", "why_findings"),
    ("purpose", "restricted to", "why_free"),
    ("purpose", "constrained by", "why_authorized"),

    ("root", "organizes", "families"),
    ("families", "includes", "fam_nmap"),
    ("families", "includes", "fam_cve"),
    ("families", "includes", "fam_web"),
    ("families", "includes", "fam_recon"),
    ("families", "includes", "fam_discover"),
    ("families", "will grow via", "fam_planned"),

    ("root", "exposes", "cli"),
    ("cli", "includes", "cli_core"),
    ("cli", "includes", "cli_meta"),
    ("cli", "includes", "cli_nmap"),
    ("cli", "includes", "cli_cve"),
    ("cli", "includes", "cli_web"),
    ("cli", "includes", "cli_recon"),
    ("cli", "includes", "cli_discover"),

    ("root", "is implemented by", "code"),
    ("code", "contains", "pkg_config"),
    ("code", "contains", "pkg_bot"),
    ("code", "contains", "pkg_nmap"),
    ("code", "contains", "pkg_scan"),
    ("code", "contains", "pkg_agent"),
    ("code", "contains", "pkg_cve"),
    ("code", "contains", "pkg_vulscan"),
    ("code", "contains", "pkg_wstg"),
    ("code", "contains", "pkg_ops"),

    ("root", "processes", "dataflow"),
    ("dataflow", "starts from", "flow_nmap"),
    ("flow_nmap", "becomes", "flow_llm"),
    ("dataflow", "includes", "flow_wstg"),
    ("dataflow", "includes", "flow_recon"),
    ("dataflow", "includes", "flow_discover"),

    ("root", "is constrained by", "safety"),
    ("safety", "defaults to", "safe_off"),
    ("safety", "requires", "safe_allowlist"),
    ("safety", "defaults to", "safe_dry"),
    ("safety", "prefers", "safe_ingest"),
    ("safety", "enforces", "safe_templates"),
    ("safety", "guaranteed by", "safe_runner"),

    ("root", "is set by", "configsec"),
    ("configsec", "via", "cfg_file"),
    ("configsec", "via", "cfg_env"),
    ("configsec", "includes", "cfg_new"),

    ("root", "is verified by", "quality"),
    ("quality", "includes", "q_go"),
    ("quality", "includes", "q_py"),
    ("quality", "includes", "q_ci"),
    ("quality", "includes", "q_drift"),

    ("root", "tracks", "roadmap"),
    ("roadmap", "includes", "rm_secrets"),
    ("roadmap", "includes", "rm_deps"),
    ("roadmap", "includes", "rm_cloud"),
    ("roadmap", "includes", "rm_chain"),
    ("roadmap", "includes", "rm_skills"),
    ("roadmap", "includes", "rm_enrich"),

    ("root", "is documented by", "meta"),
    ("meta", "uses", "meta_cxl"),
    ("meta", "uses", "meta_comments"),
    ("meta", "uses", "meta_versions"),
]

ROOT = "root"
TITLE = "hackbot — mind map v2 (overview, annotated)"
DESCRIPTION = "What hackbot is, what it does, and why it is built this way?"
SUBJECT = "hackbot, Go, security agents, WSTG, recon, nmap, concept map, v2"


def esc(text: str) -> str:
    """Escape a string for safe use in an XML attribute (quotes included)."""
    return html.escape(text, quote=True)


def build() -> tuple[str, str]:
    """Render (cxl_xml, txt_outline) from CONCEPTS + EDGES."""
    # Stable concept ids: c1.. in declaration order.
    cid = {key: f"c{i}" for i, (key, _, _) in enumerate(CONCEPTS, start=1)}

    # One linking-phrase id per edge (l1..), plus the connection triples.
    link_ids: list[tuple[str, str]] = []  # (id, label)
    conns: list[tuple[str, str, str]] = []  # (from_cid, link_id, to_cid)
    for i, (parent, phrase, child) in enumerate(EDGES, start=1):
        lid = f"l{i}"
        link_ids.append((lid, phrase))
        conns.append((cid[parent], lid, cid[child]))

    # ---- layout: depth = BFS distance from root; one row per node per depth ----
    children_of: dict[str, list[str]] = defaultdict(list)
    for parent, _, child in EDGES:
        children_of[parent].append(child)
    depth: dict[str, int] = {ROOT: 0}
    queue = deque([ROOT])
    while queue:  # breadth-first so depth is the shortest path
        node = queue.popleft()
        for child in children_of[node]:
            if child not in depth:
                depth[child] = depth[node] + 1
                queue.append(child)
    # Group concepts by depth in declaration order, then assign coordinates.
    rows: dict[int, list[str]] = defaultdict(list)
    for key, _, _ in CONCEPTS:
        rows[depth.get(key, 99)].append(key)
    pos: dict[str, tuple[int, int]] = {}
    for d, keys in rows.items():
        for i, key in enumerate(keys):
            pos[key] = (60 + 380 * d, 40 + 46 * i)

    # ---- CXL ----
    lines: list[str] = []
    lines.append('<?xml version="1.0" encoding="UTF-8"?>')
    lines.append("<!--")
    lines.append("  hackbot — concept map v2 (overview, annotated)")
    lines.append("  Format: CXL (Concept Map Extensible Language), IHMC CmapTools.")
    lines.append("  Open with CmapTools (https://cmap.ihmc.us/) via File -> Open.")
    lines.append("  Every edge reads as a proposition: concept -> linking phrase -> concept.")
    lines.append("  Generated by docs/mindmap/build.py — edit that file, then re-run it.")
    lines.append("-->")
    lines.append('<cmap xmlns="http://cmap.ihmc.us/xml/cmap/"')
    lines.append('      xmlns:dc="http://purl.org/dc/elements/1.1/">')
    lines.append("")
    lines.append("    <res-meta>")
    lines.append(f"        <dc:title>{esc(TITLE)}</dc:title>")
    lines.append(f"        <dc:description>{esc(DESCRIPTION)}</dc:description>")
    lines.append(f"        <dc:subject>{esc(SUBJECT)}</dc:subject>")
    lines.append('        <dc:creator><vcard:FN xmlns:vcard="http://www.w3.org/2001/vcard-rdf/3.0#">hackbot project</vcard:FN></dc:creator>')
    lines.append("        <dc:format>x-cmap/text-xml</dc:format>")
    lines.append("        <dc:publisher>IHMC CmapTools</dc:publisher>")
    lines.append("    </res-meta>")
    lines.append("")
    lines.append(f'    <map root-id="{cid[ROOT]}"')
    lines.append(f'         header="{esc(TITLE)}"')
    lines.append('         footer="github.com/rjwashi/hackbot — format: CmapTools CXL (generated)">')
    lines.append("")
    lines.append("        <!-- ============================ CONCEPTS ============================ -->")
    lines.append("        <concept-list>")
    for key, label, comment in CONCEPTS:
        lines.append(f'            <concept id="{cid[key]}" label="{esc(label)}"')
        lines.append(f'                     long-comment="{esc(comment)}"/>')
    lines.append("        </concept-list>")
    lines.append("")
    lines.append("        <!-- ========================= LINKING PHRASES ========================= -->")
    lines.append("        <linking-phrase-list>")
    for lid, phrase in link_ids:
        lines.append(f'            <linking-phrase id="{lid}" label="{esc(phrase)}"/>')
    lines.append("        </linking-phrase-list>")
    lines.append("")
    lines.append("        <!-- =========================== CONNECTIONS =========================== -->")
    lines.append("        <connection-list>")
    for i, (parent, phrase, child) in enumerate(EDGES, start=1):
        lines.append(f'            <!-- {parent} -> {child}: {phrase} -->')
        lines.append(f'            <connection from-id="{cid[parent]}" to-id="l{i}"/>')
        lines.append(f'            <connection from-id="l{i}" to-id="{cid[child]}"/>')
    lines.append("        </connection-list>")
    lines.append("")
    lines.append("        <!-- ===================== CONCEPT LAYOUT (x, y) ====================== -->")
    lines.append("        <concept-appearance-list>")
    for key, _, _ in CONCEPTS:
        x, y = pos[key]
        lines.append(f'            <concept-appearance id="{cid[key]}" x="{x}" y="{y}"/>')
    lines.append("        </concept-appearance-list>")
    lines.append("")
    lines.append("        <!-- ================== LINKING PHRASE LAYOUT (x, y) ================== -->")
    lines.append("        <linking-phrase-appearance-list>")
    for i, (parent, _, child) in enumerate(EDGES, start=1):
        px, py = pos[parent]
        cx, cy = pos[child]
        lines.append(f'            <linking-phrase-appearance id="l{i}" x="{(px + cx) // 2}" y="{(py + cy) // 2}"/>')
    lines.append("        </linking-phrase-appearance-list>")
    lines.append("")
    lines.append("    </map>")
    lines.append("</cmap>")
    cxl = "\n".join(lines) + "\n"

    # ---- TXT outline (tree walk; each node printed once) ----
    label_of = {key: label for key, label, _ in CONCEPTS}  # key -> display label
    phrase_of = {(parent, child): phrase for parent, phrase, child in EDGES}  # edge -> label
    txt: list[str] = [f'{CONCEPTS[0][1]}  (mind map v2 — overview, annotated)', ""]
    visited = {ROOT}

    def walk(node: str, prefix: str) -> None:
        kids = [c for c in children_of.get(node, []) if c not in visited]  # edge order
        for idx, child in enumerate(kids):
            last = idx == len(kids) - 1
            branch = "└── " if last else "├── "
            visited.add(child)
            txt.append(f"{prefix}{branch}{phrase_of[(node, child)]} → {label_of[child]}")
            walk(child, prefix + ("    " if last else "│   "))

    walk(ROOT, "")
    txt.append("")
    txt.append("Concepts marked '[ ]' are roadmap items. Most concepts carry a")
    txt.append("long-comment in the .cxl explaining the reasoning (open it in CmapTools).")
    return cxl, "\n".join(txt) + "\n"


def main() -> None:
    here = Path(__file__).resolve().parent
    cxl, txt = build()
    (here / "v2-overview.cxl").write_text(cxl, encoding="utf-8", newline="\n")
    (here / "v2-overview.txt").write_text(txt, encoding="utf-8", newline="\n")
    print("wrote v2-overview.cxl and v2-overview.txt")


if __name__ == "__main__":
    main()

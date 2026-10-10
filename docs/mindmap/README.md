# hackbot concept maps

Living concept maps of the hackbot project, stored in **CmapTools** format so
they open directly in [CmapTools](https://cmap.ihmc.us/). They grow as the
project grows, so each meaningful milestone gets its own version.

## Format

- **`.cxl`** — Concept Map Extensible Language (XML), the IHMC CmapTools format.
  This is the map of record. Open it in CmapTools with *File → Open*.
  Each edge is a proposition: *concept → linking phrase → concept*.
- **`.txt`** — a plain-text rendering of the same map, easy to read in the
  repo or a terminal. Keep it in sync with the `.cxl`.

Node `long-comment`s (CmapTools concept comments) are used to explain concepts
to someone who does not know hackbot yet. In `v4` almost every concept carries a
long-comment explaining *why* the design is the way it is and which alternatives
were rejected — open the map in CmapTools and hover/click a concept to read it.

## Versions

| Map (CmapTools) | Plain text | Focus | Status |
|-----------------|-----------|-------|--------|
| `v1-overview.cxl` | `v1-overview.txt` | Project shape at the nmap-agent milestone | archived |
| `v2-overview.cxl` | `v2-overview.txt` | Five agent families + shared engine | archived |
| `v3-overview.cxl` | `v3-overview.txt` | Seven families (adds secrets + deps) and the recon footprint chain | archived |
| `v4-overview.cxl` | `v4-overview.txt` | Eight families (adds the skill-security rubric family) | current |
| `final-annotated.cxl` | — | Every concept explained for a newcomer | planned |

## How to read a map

- Each **arrow** is a proposition: *concept — linking phrase → concept*.
- `→` inside a label marks **data flow** (what becomes what).
- `[ ]` marks **roadmap** items.

## Keeping it current

`v4` is generated: `build.py` holds the whole map as one structure
(`CONCEPTS` + `EDGES`) and emits both `v4-overview.cxl` and `v4-overview.txt`
from it, so the two encodings cannot drift (the same reason the repo has Go
drift-tests for its docs). Regenerate with:

```bash
python docs/mindmap/build.py
```

If you rearrange the map in CmapTools, port those edits back into `build.py` and
re-run it so the script stays authoritative. Add a new `vN-*.cxl` (+ `.txt`
mirror) when a milestone lands, and update the table above. Keep older versions
untouched so the evolution stays visible.

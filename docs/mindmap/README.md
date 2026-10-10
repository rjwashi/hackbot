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
to someone who does not know hackbot yet.

## Versions

| Map (CmapTools) | Plain text | Focus | Status |
|-----------------|-----------|-------|--------|
| `v1-overview.cxl` | `v1-overview.txt` | Project shape at the nmap-agent milestone | current |
| `v2-*.cxl` | `v2-*.txt` | Next milestone (see ROADMAP) | planned |
| `v3-*.cxl` | `v3-*.txt` | Following milestone | planned |
| `final-annotated.cxl` | — | Every concept explained for a newcomer | planned |

## How to read a map

- Each **arrow** is a proposition: *concept — linking phrase → concept*.
- `→` inside a label marks **data flow** (what becomes what).
- `[ ]` marks **roadmap** items.

## Keeping it current

Add a new `vN-*.cxl` (+ `.txt` mirror) when a milestone lands, and update the
table above. Keep older versions untouched so the evolution stays visible.

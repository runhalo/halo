# Changelog

## 1.2.1 (2026-03-28)

### Rule & Pack Expansion

- **26 COPPA rules** included in free tier
- **Pro tier** unlocks 180+ rules across 13 jurisdictions
- Updated README with full rule and pack listing
- Added 8 unit tests covering rule loading, pattern validation, and ASAA verification

## 1.1.0 (2026-03-21)

### Compliance Engine Update

- Engine updated to v1.1.0 with COPPA rules and compliance packs
- Framework profiles expanded: Vue and Svelte support added
- Improved false positive reduction through import graph analysis
- Data flow tracing for Tier 2 enrichment

## 1.0.0 (2026-03-14)

### First Stable Release

- Promoted to v1.0.0 — production ready
- License activation via `halo.activate` command
- Full rule coverage across 9+ regulatory frameworks
- Scan-on-type debouncing (500ms) for smooth editing experience
- Published to VS Code Marketplace

## 0.4.0 (2026-03-04)

### Major Update — Multi-Jurisdiction Compliance

- **Over 100 rules across 9 regulatory packs** — up from 25 rules in v0.1.0
- **New packs**: AU Online Safety Act (12 rules), UK AADC (15 rules), EU DSA Article 28 (10 rules), Utah SB 142 (5 rules), AU Safety by Design (6 rules), AI-Generated Code Audit (6 rules), Canada AADCA (15 rules)
- **AST analysis** — Tree-sitter powered code understanding reduces false positives
- **Framework profiles** — Built-in allowlists for Next.js, Django, and Rails
- **Compliance scoring** — 100-point scale with letter grades (A+ through F)
- Engine updated to v0.4.0

## 0.1.0 (2026-02-28)

### Initial Release

- Real-time COPPA 2.0 risk scanning in VS Code
- 20 COPPA rules + 5 ethical design rules
- Inline diagnostics with severity levels
- Scan on save and scan on type (configurable)
- Commands: Scan File, Scan Workspace, Explain Rule, Disable
- Supports: TypeScript, JavaScript, TSX, JSX, Python, Swift, HTML
- Quick-fix suggestions for common patterns
- Configurable severity threshold

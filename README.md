<p align="center">
  <img src="assets/badges/scanned-with-halo-dark.svg" alt="Scanned with Halo" width="180" />
</p>

<h1 align="center">Halo</h1>

<p align="center">
  <strong>Open-source children's privacy compliance scanner</strong>
</p>

<p align="center">
  <a href="https://runhalo.dev">Website</a> &middot;
  <a href="#quickstart">Quickstart</a> &middot;
  <a href="#what-halo-scans-for">What It Scans For</a> &middot;
  <a href="#packages">Packages</a> &middot;
  <a href="https://github.com/runhalo/halo/issues">Issues</a>
</p>

<p align="center">
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://www.npmjs.com/package/@runhalo/cli"><img src="https://img.shields.io/npm/v/@runhalo/cli.svg" alt="npm version"></a>
  <a href="https://github.com/runhalo/halo/actions"><img src="https://img.shields.io/github/actions/workflow/status/runhalo/halo/halo-audit.yml" alt="CI"></a>
</p>

---

Halo scans your codebase for children's privacy compliance risks. One command. Results in seconds. Runs locally.

```bash
npx runhalo scan .
```

```
  Halo v1.2.2

  Scanning... 142 files analyzed

  src/auth/social-login.ts:24
    coppa-auth-001  Unverified social login detected     CRITICAL

  src/services/analytics.ts:89
    coppa-tracking-003  Third-party ad tracker found      HIGH

  src/components/Chat.tsx:15
    coppa-ext-011  Unmoderated third-party chat           HIGH

  3 potential issues found | 142 files scanned | Score: 82/100 (B)
```

## Why Halo?

Children spend more time inside software than they do in classrooms. The apps they use every day are built by engineers who rarely see the regulatory landscape they're shipping into.

COPPA 2.0 takes effect **April 22, 2026**. Penalties up to **$53,088 per violation per day**. Most engineering teams have never audited their codebase against it.

Halo surfaces potential compliance risks early, before code ships to production.

> **Note:** Halo is a diagnostic tool, not legal advice. It identifies code patterns that correlate with compliance risks. Consult qualified legal counsel for compliance determinations.

## Quickstart

### CLI

```bash
# Scan current directory
npx runhalo scan .

# Scan with JSON output
npx runhalo scan ./src --format json

# Scan with SARIF output (for GitHub Security tab)
npx runhalo scan . --format sarif --output results.sarif

# Filter by severity
npx runhalo scan . --severity critical,high
```

### VS Code Extension

Install `halo-vscode` from the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=runhalo.halo-vscode):

- Highlights potential issues inline as you work
- Fix suggestions for common patterns
- Configurable severity threshold

### GitHub Action

Add Halo to your CI pipeline to scan every pull request:

```yaml
# .github/workflows/halo.yml
name: Halo Compliance Scan
on:
  pull_request:
    paths: ['**.ts', '**.js', '**.tsx', '**.jsx', '**.py', '**.swift']

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm install @runhalo/cli
      - run: npx runhalo scan . --format sarif --output results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

See [`templates/github-actions/`](templates/github-actions/) for ready-to-use workflow templates.

### MCP Server

Use `@runhalo/mcp` to integrate Halo with Claude Code or other MCP-compatible AI tools:

```json
{
  "mcpServers": {
    "halo": {
      "command": "npx",
      "args": ["@runhalo/mcp"]
    }
  }
}
```

## What Halo Scans For

Halo detects children's privacy violations: unauthorized data collection, missing consent flows, tracking without child-directed flags, age verification gaps, dark patterns, and data retention issues.

### Free — COPPA (US)

25 rules covering US children's privacy law, included with every install:

| ID | Rule | Severity |
|:---|:-----|:---------|
| `coppa-auth-001` | Unverified social login providers | Critical |
| `coppa-data-002` | PII in URL parameters | Critical |
| `coppa-tracking-003` | Third-party ad trackers | Critical |
| `coppa-geo-004` | Precise geolocation collection | Critical |
| `coppa-retention-005` | Missing data retention limits | High |
| `coppa-sec-006` | Unencrypted PII transmission | Critical |
| `coppa-audio-007` | Unauthorized audio recording | Critical |
| `coppa-ui-008` | Missing privacy policy on registration | High |
| `coppa-flow-009` | Direct contact without parent email | High |
| `coppa-sec-010` | Weak default passwords | Medium |
| `coppa-ext-011` | Unmoderated third-party chat | High |
| `coppa-bio-012` | Biometric data collection | Critical |
| `coppa-notif-013` | Push notifications without consent | Medium |
| `coppa-ugc-014` | UGC without PII filter | High |
| `coppa-sec-015` | XSS vulnerabilities | High |
| `coppa-cookies-016` | Missing cookie consent | Medium |
| `coppa-ext-017` | Unwarned external links | Medium |
| `coppa-analytics-018` | Analytics user ID mapping | High |
| `coppa-edu-019` | School official verification bypass | High |
| `coppa-default-020` | Default public profile visibility | High |

Plus 5 additional COPPA 2.0 rules effective April 22, 2026.

### Pro — Global Coverage

Unlock **180+ rules across 13 jurisdictions** with [Halo Pro](https://runhalo.dev/#pricing):

| Jurisdiction | Coverage |
|:-------------|:---------|
| UK Age Appropriate Design Code (AADC) | Age-appropriate defaults, profiling, nudge techniques |
| EU Digital Services Act (DSA) | Ad profiling, autoplay, recommendation algorithms |
| Australia Online Safety Act | Age verification, content moderation, data retention |
| Australia Safety by Design | Default privacy, reporting, location data |
| Canada AADCA | Dark patterns, in-app purchases, data minimization |
| Utah SB 142 | Parental consent, DM restrictions, search visibility |
| Brazil LGPD | Best interest principle, parental consent |
| India DPDP | Tracking bans, behavioral monitoring |
| South Korea PIPA | Parental consent, data retention |
| Canada PIPEDA | Meaningful consent, behavioral advertising |
| GDPR Article 8 (EU) | Age gates, data minimization, erasure rights |
| Ethical Design | Infinite scroll, loot boxes, streak mechanics |
| AI Code Audit | AI-generated code compliance risks |

[Start scanning with Pro &rarr;](https://runhalo.dev/#pricing)

### Suppression

Suppress individual findings with inline comments:

```typescript
// halo-ignore coppa-auth-001
const auth = signInWithPopup(provider);
```

## Plans

| | Free | Pro | Business |
|:--|:-----|:----|:---------|
| **Price** | $0 | $29/mo | $99/mo |
| **COPPA rules (US)** | &#10003; | &#10003; | &#10003; |
| **All 180+ rules (13 jurisdictions)** | | &#10003; | &#10003; |
| **AI-powered review** | &#10003; | &#10003; | &#10003; |
| **CLI + VS Code + GitHub Action** | &#10003; | &#10003; | &#10003; |
| **PDF, SARIF, HTML reports** | | &#10003; | &#10003; |
| **Priority support** | | &#10003; | &#10003; |
| **Compliance attestation** | | | &#10003; |
| **Recurring scans + drift alerts** | | | &#10003; |
| **Team collaboration** | | | &#10003; |

[See pricing &rarr;](https://runhalo.dev/#pricing)

## Packages

| Package | Description | npm |
|:--------|:------------|:----|
| [`@runhalo/engine`](packages/engine/) | Core scanning engine | [![npm](https://img.shields.io/npm/v/@runhalo/engine.svg)](https://www.npmjs.com/package/@runhalo/engine) |
| [`@runhalo/cli`](packages/cli/) | CLI scanner (`npx runhalo scan .`) | [![npm](https://img.shields.io/npm/v/@runhalo/cli.svg)](https://www.npmjs.com/package/@runhalo/cli) |
| [`@runhalo/mcp`](packages/mcp/) | MCP server for AI tools | [![npm](https://img.shields.io/npm/v/@runhalo/mcp.svg)](https://www.npmjs.com/package/@runhalo/mcp) |
| [`halo-vscode`](packages/vscode/) | VS Code extension | [Marketplace](https://marketplace.visualstudio.com/items?itemName=runhalo.halo-vscode) |

## Supported Languages

JavaScript, TypeScript, Python, Swift, Java, Kotlin, HTML, Vue, Svelte, SQL, and more.

## Output Formats

| Format | Flag | Use Case |
|:-------|:-----|:---------|
| Text | `--format text` (default) | Terminal output |
| JSON | `--format json` | CI pipelines, tooling |
| SARIF | `--format sarif` | GitHub Security tab |

## Development

```bash
git clone https://github.com/runhalo/halo.git
cd halo
npm install
npm run build
npm test
```

## "Scanned with Halo" Badge

```markdown
[![Scanned with Halo](https://raw.githubusercontent.com/runhalo/halo/main/assets/badges/scanned-with-halo-dark.svg)](https://runhalo.dev)
```

## Contributing

We welcome contributions! Before submitting a PR:
1. Run `npm test` to ensure all tests pass
2. Run `npm run build` to verify the build
3. Follow existing code patterns

## License

Apache License 2.0. See [LICENSE](LICENSE).

---

<p align="center">
  <sub>Halo identifies potential compliance risks in your codebase. It is not legal advice and does not guarantee regulatory compliance. Consult qualified legal counsel for compliance determinations.</sub>
</p>

<p align="center">
  <sub>Built by <a href="https://mindfulmedia.org">Mindful Media</a> in Santa Monica, California</sub>
</p>

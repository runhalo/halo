<p align="center">
  <img src="assets/badges/scanned-with-halo-dark.svg" alt="Scanned with Halo" width="180" />
</p>

<h1 align="center">Halo</h1>

<p align="center">
  <strong>COPPA Compliance Scanner for Children's Apps</strong>
</p>

<p align="center">
  <a href="https://runhalo.dev">Website</a> &middot;
  <a href="#quickstart">Quickstart</a> &middot;
  <a href="#coppa-rules">COPPA Rules</a> &middot;
  <a href="#packages">Packages</a> &middot;
  <a href="https://github.com/runhalo/halo/issues">Issues</a>
</p>

<p align="center">
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://www.npmjs.com/package/@runhalo/cli"><img src="https://img.shields.io/npm/v/@runhalo/cli.svg" alt="npm version"></a>
  <a href="https://github.com/runhalo/halo/actions"><img src="https://img.shields.io/github/actions/workflow/status/runhalo/halo/halo-audit.yml" alt="CI"></a>
</p>

---

Halo scans your codebase for COPPA compliance risks. One command. Results in seconds. Runs locally.

```bash
npx runhalo scan .
```

```
  Halo v1.3.1

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

## COPPA Rules

Halo ships with 26 rules covering the Children's Online Privacy Protection Act (COPPA), including COPPA 2.0 provisions effective April 22, 2026.

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

Plus 6 additional rules covering COPPA 2.0 provisions (biometric identifiers, behavioral advertising restrictions, data security requirements, and more).

See [`docs/rules-reference.md`](docs/rules-reference.md) for detailed descriptions and fix guidance.

### Suppression

Suppress individual findings with inline comments:

```typescript
// halo-ignore coppa-auth-001
const auth = signInWithPopup(provider);
```

## Need More Jurisdictions?

Halo Pro and Business tiers unlock additional compliance rules for international regulations. Activate with your license key:

```bash
halo activate <key>
```

Visit [runhalo.dev/pricing](https://runhalo.dev/pricing) for details.

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

`npm install` points your clone's git hooks at `.githooks` (via `core.hooksPath`),
which installs a fail-closed pre-push check that the rule set is the COPPA-only
pack. To enable it without a full install, run `git config core.hooksPath .githooks`.
You can run the same check anytime with `npm run check:rules`. The check also runs
in CI on every push and pull request.

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

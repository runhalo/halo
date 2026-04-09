# @runhalo/cli

**Halo CLI** — scan your codebase for children's privacy compliance risks.

[![npm](https://img.shields.io/npm/v/@runhalo/cli.svg)](https://www.npmjs.com/package/@runhalo/cli)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

## What It Does

One command scans your codebase for COPPA violations, dark patterns, unauthorized data collection, missing consent flows, and age verification gaps. It reads your code the way a regulator would.

**COPPA 2.0 enforcement begins April 22, 2026.** Penalties up to $53,088 per violation per day.

## Quickstart

```bash
# Scan current directory
npx runhalo scan .

# JSON output for CI pipelines
npx runhalo scan . --format json

# SARIF output for GitHub Security tab
npx runhalo scan . --format sarif --output results.sarif

# Filter by severity
npx runhalo scan . --severity critical,high
```

## Example Output

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

## What's Included

**Free:** 25 COPPA rules (US children's privacy law), AI false positive filtering, JSON output.

**Pro ($29/mo):** All 180+ rules across 13 jurisdictions (UK AADC, EU DSA, Australia, Canada, and more), PDF/SARIF/HTML reports, GitHub Action for CI/CD, priority support.

**Business ($99/mo):** Everything in Pro plus compliance attestation, recurring scans with drift alerts, and team collaboration.

[See pricing &rarr;](https://runhalo.dev/#pricing)

## Suppression

```typescript
// halo-ignore coppa-auth-001
const auth = signInWithPopup(provider);
```

## Output Formats

| Format | Flag | Use Case |
|:-------|:-----|:---------|
| Text | `--format text` (default) | Terminal output |
| JSON | `--format json` | CI pipelines, tooling |
| SARIF | `--format sarif` | GitHub Security tab |

## Supported Languages

JavaScript, TypeScript, Python, Swift, Java, Kotlin, HTML, Vue, Svelte, SQL, and more.

## Links

- [Website](https://runhalo.dev)
- [Documentation](https://github.com/runhalo/halo)
- [VS Code Extension](https://marketplace.visualstudio.com/items?itemName=runhalo.halo-vscode)
- [Report an Issue](https://github.com/runhalo/halo/issues)

## License

Apache 2.0 — [Mindful Media](https://mindfulmedia.org)

---

*Halo identifies potential compliance risks in your codebase. It is not legal advice. Consult qualified legal counsel for compliance determinations.*

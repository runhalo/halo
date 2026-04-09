# Halo for VS Code

Children's privacy compliance scanner for your editor. Highlights potential COPPA violations as you work.

## What It Does

Halo scans your code for children's privacy compliance risks: unauthorized data collection, missing consent flows, tracking without child-directed flags, age verification gaps, and dark patterns.

**COPPA 2.0 enforcement begins April 22, 2026.** Penalties up to $53,088 per violation per day.

## Features

- **Inline diagnostics** — highlights compliance risks as you code
- **Fix suggestions** — recommended remediations for common patterns
- **Framework-aware** — built-in profiles for React, Next.js, Vue, Angular, Django, Rails
- **Multi-language** — TypeScript, JavaScript, Python, Swift, Java, Kotlin, HTML, and more
- **Configurable severity** — filter by Critical, High, Medium, Low
- **COPPA 2.0 countdown** — days until enforcement deadline

## Quick Start

1. Install the extension from the VS Code Marketplace
2. Open a project
3. Issues appear automatically in the Problems panel and inline

## Commands

| Command | Description |
|:--------|:------------|
| `Halo: Scan Current File` | Scan the active file |
| `Halo: Scan Workspace` | Scan all files in the workspace |
| `Halo: Activate License` | Activate a Pro or Business license key |
| `Halo: Explain Rule` | Get details on a specific rule |

## Configuration

| Setting | Default | Description |
|:--------|:--------|:------------|
| `halo.enable` | `true` | Enable/disable scanning |
| `halo.severity` | `all` | Minimum severity: `all`, `critical`, `high`, `medium` |
| `halo.scanOnSave` | `true` | Scan when files are saved |

## Suppressing Rules

```typescript
// halo-ignore coppa-auth-001
const login = useGoogleLogin();
```

## Plans

| | Free | Pro | Business |
|:--|:-----|:----|:---------|
| **COPPA rules (US)** | &#10003; | &#10003; | &#10003; |
| **All 180+ rules (13 jurisdictions)** | | &#10003; | &#10003; |
| **AI-powered review** | &#10003; | &#10003; | &#10003; |
| **PDF, SARIF, HTML reports** | | &#10003; | &#10003; |
| **Compliance attestation** | | | &#10003; |

[See pricing →](https://runhalo.dev/#pricing)

## Links

- [Website](https://runhalo.dev)
- [GitHub](https://github.com/runhalo/halo)
- [CLI](https://www.npmjs.com/package/@runhalo/cli)
- [Report an Issue](https://github.com/runhalo/halo/issues)

## Requirements

VS Code 1.85.0 or later

## License

Apache License 2.0

---

*Halo identifies potential compliance risks in your codebase. It is not legal advice. Built by [Mindful Media](https://mindfulmedia.org) in Santa Monica, California.*

# Halo CI/CD Templates

Ready-to-use GitHub Actions workflows for integrating Halo into your CI/CD pipeline.

## Choose Your Template

| Template | File | Best For |
|----------|------|----------|
| **Basic** | `halo-basic.yml` | Quick setup. Scans on push/PR, uploads results to GitHub Security tab. |
| **Standard** | `halo-standard.yml` | Most teams. Adds severity-based pass/fail — blocks merges on critical issues. |
| **Full** | `halo-full.yml` | Production. Adds PR comment summaries with severity breakdown and file-level details. |

## Quick Start

1. Copy your chosen template to `.github/workflows/halo.yml` in your repository
2. Commit and push
3. Open a pull request to see Halo in action

```bash
# Example: copy the standard template
mkdir -p .github/workflows
cp halo-standard.yml .github/workflows/halo.yml
```

## What Each Template Does

### Basic (`halo-basic.yml`)
- Runs on every push to `main` and every PR
- Uploads SARIF results to GitHub's Security tab
- No build blocking — informational only

### Standard (`halo-standard.yml`)
- Runs on PRs when code files change (15+ language extensions)
- Uploads SARIF to GitHub Security tab
- **Blocks merge on critical violations**
- Warns on high severity issues
- Caches npm for faster runs

### Full (`halo-full.yml`)
- Everything in Standard, plus:
- **Posts a PR comment** with severity breakdown
- Lists top issues by file and line number
- Updates existing comment on new pushes (no spam)
- Shows scan stats (files scanned, severity counts)

## Supported File Types

All templates scan files with these extensions:
`.ts` `.tsx` `.js` `.jsx` `.py` `.swift` `.html` `.php` `.kt` `.java` `.cs` `.cpp` `.vue` `.svelte`

## Configuration

### Suppress specific rules
Add a `.haloignore` file to your repo root:
```
# Suppress specific rules
coppa-ext-017
coppa-sec-006
```

### Inline suppression
```typescript
// halo-ignore coppa-auth-001 — verified: age gate handled by middleware
const login = useGoogleLogin();
```

## Requirements

- Node.js 20+
- GitHub Actions runner (ubuntu-latest recommended)
- `security-events: write` permission for SARIF upload
- `pull-requests: write` permission for PR comments (Full template only)

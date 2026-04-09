# Getting Started

## Installation

### Quick scan (no install)

```bash
npx runhalo scan .
```

### Global install

```bash
npm install -g @runhalo/cli
runhalo scan .
```

### Project dependency

```bash
npm install --save-dev @runhalo/cli
npx runhalo scan .
```

## Your First Scan

Run Halo on your project directory:

```bash
npx runhalo scan .
```

Halo will:
1. Discover all supported source files (TypeScript, JavaScript, Python, Swift, Java, Kotlin, HTML, PHP, C++, C#, Vue, Svelte, SQL, QML)
2. Analyze each file against 25 rules (20 COPPA + 5 ethical design)
3. Report findings with severity levels, file locations, and fix suggestions

### Example Output

```
  Halo COPPA Risk Scanner v0.1.1

  Scanning... 142 files analyzed

  src/auth/social-login.ts:24
    coppa-auth-001  Unverified social login detected     CRITICAL
    Fix: Implement age gate before social authentication

  src/services/analytics.ts:89
    coppa-tracking-003  Third-party ad tracker found      HIGH
    Fix: Replace ad tracking with privacy-safe analytics

  3 potential issues found | 142 files scanned | 25 checks applied
```

## Output Formats

### Text (default)

```bash
npx runhalo scan . --format text
```

Human-readable output for terminal review.

### JSON

```bash
npx runhalo scan . --format json --output results.json
```

Machine-readable output for CI pipelines and tooling. Includes full violation details, severity, file paths, line numbers, fix suggestions, and remediation metadata.

### SARIF

```bash
npx runhalo scan . --format sarif --output results.sarif
```

Static Analysis Results Interchange Format. Upload to GitHub's Security tab or integrate with any SARIF-compatible tool.

## Scan Specific Directories

```bash
# Scan only the src directory
npx runhalo scan ./src

# Scan multiple directories
npx runhalo scan ./src ./lib ./components
```

## Filter by Severity

```bash
# Only critical and high
npx runhalo scan . --severity critical,high

# Only critical
npx runhalo scan . --severity critical
```

## Next Steps

- [Rules Reference](rules-reference.md) — Understand what each rule detects
- [Configuration](configuration.md) — Suppress rules, customize thresholds
- [CI/CD Integration](ci-cd.md) — Add Halo to your build pipeline
- [VS Code Extension](vscode.md) — Get real-time scanning in your editor

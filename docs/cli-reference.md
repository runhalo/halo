# CLI Reference

## Commands

### `runhalo scan <path>`

Scan files for COPPA risks and ethical design issues.

```bash
npx runhalo scan .
npx runhalo scan ./src
npx runhalo scan ./src ./lib
```

#### Options

| Flag | Description | Default |
|:-----|:-----------|:--------|
| `--format <type>` | Output format: `text`, `json`, `sarif` | `text` |
| `--output <file>` | Write results to file instead of stdout | — |
| `--severity <levels>` | Filter by severity: `critical`, `high`, `medium`, `low` | all |
| `--include <patterns>` | Glob patterns for files to include | all supported extensions |
| `--exclude <patterns>` | Glob patterns for files to exclude | `node_modules`, `.git`, etc. |
| `--ethical` | Include ethical design rules in scan | disabled |
| `--ethical-preview` | Preview ethical rules (same as `--ethical`) | disabled |

#### Examples

```bash
# Basic scan
npx runhalo scan .

# JSON output to file
npx runhalo scan . --format json --output results.json

# SARIF for GitHub Security tab
npx runhalo scan . --format sarif --output results.sarif

# Critical only
npx runhalo scan . --severity critical

# Include ethical design rules
npx runhalo scan . --ethical

# Scan TypeScript files only
npx runhalo scan . --include "**/*.ts" --include "**/*.tsx"
```

### `runhalo explain <rule-id>`

Get a detailed explanation of a specific rule.

```bash
npx runhalo explain coppa-auth-001
```

### `runhalo list-rules`

List all available rules with descriptions.

```bash
npx runhalo list-rules
```

## Exit Codes

| Code | Meaning |
|:-----|:--------|
| `0` | No violations found |
| `1` | Violations found |
| `2` | Error (invalid arguments, file not found, etc.) |

## Default Exclude Patterns

Halo automatically excludes these directories:

```
node_modules/
.git/
dist/
build/
coverage/
__pycache__/
.next/
.nuxt/
vendor/
```

## Supported Languages

| Language | Extensions |
|:---------|:-----------|
| TypeScript | `.ts`, `.tsx` |
| JavaScript | `.js`, `.jsx` |
| Python | `.py` |
| Swift | `.swift` |
| Java | `.java` |
| Kotlin | `.kt` |
| HTML | `.html` |
| Vue | `.vue` |
| Svelte | `.svelte` |
| PHP | `.php` |
| C++ | `.cpp`, `.h`, `.hpp` |
| C# | `.cs` |
| SQL | `.sql` |
| QML | `.qml` |

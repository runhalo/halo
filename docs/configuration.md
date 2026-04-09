# Configuration

## Suppression

### Inline Comments

Suppress a specific rule on the next line:

```typescript
// halo-ignore coppa-auth-001
const login = signInWithPopup(provider);
```

Or suppress on the same line:

```typescript
const login = signInWithPopup(provider); // halo-ignore coppa-auth-001
```

Add a reason for documentation:

```typescript
// halo-ignore coppa-auth-001 — age gate handled by AuthMiddleware
const login = signInWithPopup(provider);
```

### .haloignore File

Create a `.haloignore` file at your project root to suppress rules globally or for specific paths:

```
# Suppress rules globally
coppa-cookies-016
coppa-ext-017

# Suppress for specific files
src/legacy/**
vendor/**
```

## Severity Filtering

Filter scan results by severity level:

```bash
# Only critical violations
npx runhalo scan . --severity critical

# Critical and high
npx runhalo scan . --severity critical,high

# Everything except low
npx runhalo scan . --severity critical,high,medium
```

## Ethical Design Rules

Ethical design rules are opt-in. Enable them with the `--ethical` flag:

```bash
# Include ethical design rules
npx runhalo scan . --ethical
```

Ethical rules are reported as suggestions (not errors) to guide design decisions without blocking builds.

## VS Code Settings

Configure Halo in VS Code via `settings.json`:

```json
{
  "halo.enable": true,
  "halo.severity": "all",
  "halo.scanOnSave": true,
  "halo.scanOnType": true
}
```

| Setting | Type | Default | Description |
|:--------|:-----|:--------|:------------|
| `halo.enable` | boolean | `true` | Enable/disable scanning |
| `halo.severity` | string | `"all"` | Minimum severity: `all`, `critical`, `high`, `medium` |
| `halo.scanOnSave` | boolean | `true` | Scan when files are saved |
| `halo.scanOnType` | boolean | `true` | Scan while typing (debounced) |

## Engine Configuration (Programmatic)

When using `@runhalo/engine` directly:

```typescript
import { HaloEngine } from '@runhalo/engine';

const engine = new HaloEngine({
  // Filter to specific rules
  rules: ['coppa-auth-001', 'coppa-data-002'],

  // Filter by severity
  severityFilter: ['critical', 'high'],

  // Enable ethical design rules
  ethical: true,

  // Include suppressed violations in results
  includeSuppressed: true,

  // Load rules from YAML file
  rulesPath: './custom-rules.yml',
});

const violations = engine.scanFile('src/app.tsx', sourceCode);
```

## JSON Output Schema

The JSON output includes remediation metadata for each violation:

```json
{
  "totalFiles": 142,
  "totalViolations": 3,
  "results": [
    {
      "file": "src/auth/login.tsx",
      "violations": [
        {
          "ruleId": "coppa-auth-001",
          "ruleName": "Unverified Social Login Providers",
          "severity": "critical",
          "line": 24,
          "column": 5,
          "message": "...",
          "fixSuggestion": "...",
          "category": "auth",
          "language": "typescript",
          "matchType": "ast",
          "fixability": "guided",
          "remediation": {
            "fixability": "guided",
            "scaffoldId": "age-gate-auth",
            "estimatedCost": "$0.01"
          }
        }
      ]
    }
  ]
}
```

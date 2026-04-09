# CI/CD Integration

## GitHub Actions

Halo provides three ready-to-use GitHub Actions workflow templates. Copy any template to `.github/workflows/halo.yml` in your repository.

### Basic Template

Scans on every push and PR. Uploads results to GitHub's Security tab. No build blocking.

```bash
cp templates/github-actions/halo-basic.yml .github/workflows/halo.yml
```

[View template source](https://github.com/runhalo/halo/blob/main/templates/github-actions/halo-basic.yml)

### Standard Template (Recommended)

Scans PRs when code files change. Blocks merges on critical violations. Warns on high severity.

```bash
cp templates/github-actions/halo-standard.yml .github/workflows/halo.yml
```

[View template source](https://github.com/runhalo/halo/blob/main/templates/github-actions/halo-standard.yml)

### Full Template

Everything in Standard, plus PR comment summaries with severity breakdown and file-level details.

```bash
cp templates/github-actions/halo-full.yml .github/workflows/halo.yml
```

[View template source](https://github.com/runhalo/halo/blob/main/templates/github-actions/halo-full.yml)

## Minimal Setup

If you prefer a custom workflow, here's the minimal configuration:

```yaml
name: Halo
on: [pull_request]

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

## SARIF Integration

SARIF (Static Analysis Results Interchange Format) enables Halo results to appear in GitHub's Security tab alongside CodeQL and other security tools.

### Permissions Required

```yaml
permissions:
  security-events: write  # Required for SARIF upload
  pull-requests: write    # Required for PR comments (Full template only)
  contents: read          # Required for checkout
```

### Viewing Results

After a scan completes:
1. Go to your repository's **Security** tab
2. Click **Code scanning alerts**
3. Filter by **Tool: halo-coppa**

## Exit Code Strategy

Halo exits with code `1` when violations are found. Use `|| true` to continue the workflow after scanning, then check specific severity levels:

```yaml
- run: npx runhalo scan . --format json --output results.json || true

- name: Check severity
  run: |
    CRITICAL=$(cat results.json | jq '[.results[]?.violations[]? | select(.severity == "critical")] | length')
    if [ "$CRITICAL" -gt 0 ]; then
      exit 1
    fi
```

## Other CI Systems

### GitLab CI

```yaml
halo-scan:
  image: node:20
  script:
    - npm install @runhalo/cli
    - npx runhalo scan . --format json --output halo-results.json
  artifacts:
    reports:
      codequality: halo-results.json
```

### CircleCI

```yaml
jobs:
  halo-scan:
    docker:
      - image: cimg/node:20.0
    steps:
      - checkout
      - run: npm install @runhalo/cli
      - run: npx runhalo scan . --format json --output halo-results.json
      - store_artifacts:
          path: halo-results.json
```

### Generic CI

Any CI system that supports Node.js can run Halo:

```bash
npm install @runhalo/cli
npx runhalo scan . --format json --output results.json
```

Parse the JSON output to integrate with your CI system's reporting.

# @runhalo/engine

**Halo rule engine** — COPPA 2.0 risk detection via tree-sitter AST analysis.

[![npm](https://img.shields.io/npm/v/@runhalo/engine.svg)](https://www.npmjs.com/package/@runhalo/engine)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

## What it does

The engine scans source files for code patterns that may indicate COPPA 2.0 privacy risks in children's apps. It ships with **20 COPPA rules** and **5 ethical design rules**, powered by tree-sitter AST analysis and regex pattern matching.

## Install

```bash
npm install @runhalo/engine
```

## Usage

```typescript
import { HaloEngine } from '@runhalo/engine';

const engine = new HaloEngine();

// Scan a single file
const results = engine.scanFile('src/auth/login.ts', sourceCode);

// Each result includes:
// - ruleId: 'coppa-auth-001'
// - severity: 'critical' | 'high' | 'medium' | 'low'
// - message: human-readable description
// - line / column / codeSnippet
// - fixSuggestion: recommended remediation
```

## Rules

20 COPPA rules covering authentication, data collection, tracking, encryption, and consent — plus 5 ethical design rules for dark patterns like infinite scroll, streak pressure, and loot boxes.

Full rule reference: [github.com/runhalo/halo#rules](https://github.com/runhalo/halo#rules)

## Supported Languages

TypeScript, JavaScript, TSX, JSX, Python, Swift, Java, Kotlin, HTML, Vue, Svelte, PHP, C++, C#, SQL

## CLI

Most users should install the CLI instead:

```bash
npx @runhalo/cli scan .
```

See [@runhalo/cli](https://www.npmjs.com/package/@runhalo/cli) for the command-line scanner.

## License

Apache 2.0 — [Mindful Media](https://mindfulmedia.org)

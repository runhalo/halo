# MCP Server (AI Integration)

Halo's MCP (Model Context Protocol) server enables AI assistants to scan code for COPPA risks and explain findings in natural language.

## Setup

### Claude Code

Add to your Claude Code MCP configuration:

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

### Cursor

Add to your Cursor MCP settings:

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

## Available Tools

The MCP server exposes these tools to AI assistants:

### `audit_file`

Scan a single file for COPPA risks.

**Input:** File path and content
**Output:** List of violations with severity, line numbers, and fix suggestions

### `get_violations`

Get violations filtered by rule ID or severity.

**Input:** Optional filters (ruleId, severity)
**Output:** Filtered violation list

### `explain_rule`

Get a detailed explanation of a specific COPPA rule.

**Input:** Rule ID (e.g., `coppa-auth-001`)
**Output:** Rule description, detection logic, fix guidance, penalty information

### `suggest_fix`

Get a fix suggestion for a specific rule violation.

**Input:** Rule ID
**Output:** Actionable fix recommendation

## Example Interactions

With the MCP server configured, you can ask your AI assistant:

- "Scan this file for COPPA issues"
- "Explain what coppa-auth-001 means"
- "How do I fix the geolocation violation on line 42?"
- "Are there any critical privacy issues in my auth module?"

The AI assistant will use Halo's tools to provide accurate, rule-based answers rather than general advice.

## Requirements

- Node.js 20+
- An MCP-compatible AI tool (Claude Code, Cursor, etc.)

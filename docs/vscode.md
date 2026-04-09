# VS Code Extension

Halo for VS Code provides real-time COPPA 2.0 risk scanning directly in your editor.

## Installation

Search for "Halo" in the VS Code Extensions panel, or install from the command line:

```bash
code --install-extension runhalo.halo-vscode
```

## Features

### Inline Diagnostics

Halo highlights potential COPPA risks inline as you type. Issues appear with squiggly underlines colored by severity:

- 🔴 **Critical** — Red underline
- 🟠 **High** — Orange underline
- 🟡 **Medium** — Yellow underline
- 🔵 **Low** — Blue underline

### Problems Panel

All findings appear in VS Code's Problems panel (`Ctrl+Shift+M` / `Cmd+Shift+M`), organized by file and severity.

### Commands

Access Halo commands via the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`):

| Command | Description |
|:--------|:------------|
| `Halo: Scan Current File` | Scan the active file |
| `Halo: Scan Workspace` | Scan all supported files in the workspace |
| `Halo: Explain Rule` | Get a detailed explanation of a rule |
| `Halo: Disable Diagnostics` | Temporarily disable scanning |

### Scan Modes

- **Scan on Save** — Scans the file each time you save (`Ctrl+S`)
- **Scan on Type** — Scans as you type with a debounce delay

Both modes are enabled by default and can be configured in settings.

## Configuration

Open VS Code settings (`Ctrl+,` / `Cmd+,`) and search for "Halo":

| Setting | Default | Description |
|:--------|:--------|:------------|
| `halo.enable` | `true` | Enable/disable Halo scanning |
| `halo.severity` | `all` | Minimum severity: `all`, `critical`, `high`, `medium` |
| `halo.scanOnSave` | `true` | Scan files when saved |
| `halo.scanOnType` | `true` | Scan files while typing |

Or add to `settings.json`:

```json
{
  "halo.enable": true,
  "halo.severity": "high",
  "halo.scanOnSave": true,
  "halo.scanOnType": false
}
```

## Supported Languages

The extension activates for these file types:

- TypeScript (`.ts`)
- JavaScript (`.js`)
- TypeScript React (`.tsx`)
- JavaScript React (`.jsx`)
- Python (`.py`)
- Swift (`.swift`)
- HTML (`.html`)

## Suppressing Findings

Use inline comments to suppress specific findings:

```typescript
// halo-ignore coppa-auth-001 — age gate handled by middleware
const login = useGoogleLogin();
```

The diagnostic will disappear after the next scan.

/**
 * Halo VS Code Extension
 * Real-time COPPA 2.0 compliance scanning
 *
 * Provides diagnostic warnings for COPPA violations with quick-fix suggestions.
 * Scans on open, save, and while typing (debounced).
 */

import * as vscode from 'vscode';
import { HaloEngine, COPPA_RULES, Violation } from '@runhalo/engine';
import * as path from 'path';
import { getLicense, activateLicense, deactivateLicense, LicenseInfo, canUseFeature } from './license';

// Diagnostic collection name
const DIAGNOSTIC_SOURCE = 'Halo';

// Global state
let diagnosticCollection: vscode.DiagnosticCollection;
let engine: HaloEngine;
let debounceTimers: Map<string, NodeJS.Timeout> = new Map();
let currentLicense: LicenseInfo;
let statusBarItem: vscode.StatusBarItem;

// Supported language IDs
const SUPPORTED_LANGUAGES = new Set([
  'typescript', 'javascript', 'typescriptreact', 'javascriptreact',
  'python', 'swift', 'html', 'vue', 'svelte'
]);

/**
 * Activate the extension
 */
export async function activate(context: vscode.ExtensionContext): Promise<void> {
  // Initialize the rule engine with suppression enabled
  engine = new HaloEngine({
    suppressions: { enabled: true }
  });

  // Check license (non-blocking — falls back to free mode)
  currentLicense = await getLicense(context);

  // Status bar item showing license tier
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  updateStatusBar();
  statusBarItem.show();

  // Create diagnostic collection
  diagnosticCollection = vscode.languages.createDiagnosticCollection(DIAGNOSTIC_SOURCE);

  // Register license commands
  const activateCmd = vscode.commands.registerCommand('halo.activate', async () => {
    currentLicense = await activateLicense(context);
    updateStatusBar();
  });

  const deactivateCmd = vscode.commands.registerCommand('halo.deactivate', async () => {
    await deactivateLicense(context);
    currentLicense = { valid: true, tier: 'free', email: '', status: 'active', cachedAt: Date.now() };
    updateStatusBar();
  });

  // Register commands
  const scanFileCmd = vscode.commands.registerCommand('halo.scanFile', () => {
    const editor = vscode.window.activeTextEditor;
    if (editor && isSupported(editor.document)) {
      scanDocument(editor.document);
    } else {
      vscode.window.showInformationMessage('Halo: No supported file open');
    }
  });

  const scanWorkspaceCmd = vscode.commands.registerCommand('halo.scanWorkspace', () => {
    scanWorkspace();
  });

  const explainRuleCmd = vscode.commands.registerCommand('halo.explainRule', async (ruleId?: string) => {
    if (!ruleId) {
      const items = COPPA_RULES.map(rule => ({
        label: `${severityIcon(rule.severity)} ${rule.id}`,
        detail: rule.name,
        description: rule.severity.toUpperCase(),
        ruleId: rule.id
      }));

      const selected = await vscode.window.showQuickPick(items, {
        placeHolder: 'Select a COPPA rule to learn more'
      });

      if (selected) {
        ruleId = (selected as any).ruleId;
      }
    }

    if (ruleId) {
      const explanation = engine.explainRule(ruleId);
      const panel = vscode.window.createWebviewPanel(
        'haloRule',
        `Halo: ${ruleId}`,
        vscode.ViewColumn.Beside,
        {}
      );
      panel.webview.html = formatRuleExplanation(ruleId, explanation);
    }
  });

  const disableCmd = vscode.commands.registerCommand('halo.disable', () => {
    diagnosticCollection.clear();
    vscode.window.showInformationMessage('Halo diagnostics cleared');
  });

  // Register code action provider for quick fixes
  const codeActionProvider = vscode.languages.registerCodeActionsProvider(
    Array.from(SUPPORTED_LANGUAGES).map(lang => ({ language: lang })),
    new HaloCodeActionProvider(),
    { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
  );

  // Scan on document open
  const onOpen = vscode.workspace.onDidOpenTextDocument(doc => {
    if (isEnabled() && isSupported(doc)) {
      scanDocument(doc);
    }
  });

  // Scan on document save
  const onSave = vscode.workspace.onDidSaveTextDocument(doc => {
    const config = vscode.workspace.getConfiguration('halo');
    if (isEnabled() && config.get('scanOnSave', true) && isSupported(doc)) {
      scanDocument(doc);
    }
  });

  // Scan on document change (debounced)
  const onChange = vscode.workspace.onDidChangeTextDocument(event => {
    const config = vscode.workspace.getConfiguration('halo');
    if (isEnabled() && config.get('scanOnType', true) && isSupported(event.document)) {
      debouncedScan(event.document);
    }
  });

  // Clear diagnostics when document closes
  const onClose = vscode.workspace.onDidCloseTextDocument(doc => {
    diagnosticCollection.delete(doc.uri);
  });

  // Scan all open editors on activation
  vscode.window.visibleTextEditors.forEach(editor => {
    if (isEnabled() && isSupported(editor.document)) {
      scanDocument(editor.document);
    }
  });

  context.subscriptions.push(
    activateCmd, deactivateCmd,
    scanFileCmd, scanWorkspaceCmd, explainRuleCmd, disableCmd,
    codeActionProvider, onOpen, onSave, onChange, onClose,
    diagnosticCollection, statusBarItem
  );
}

/**
 * Check if Halo is enabled in settings
 */
function isEnabled(): boolean {
  return vscode.workspace.getConfiguration('halo').get('enable', true);
}

/**
 * Check if document language is supported
 */
function isSupported(document: vscode.TextDocument): boolean {
  return SUPPORTED_LANGUAGES.has(document.languageId);
}

/**
 * Debounced scan (500ms) to avoid scanning on every keystroke
 */
function debouncedScan(document: vscode.TextDocument): void {
  const key = document.uri.toString();
  const existing = debounceTimers.get(key);
  if (existing) {
    clearTimeout(existing);
  }

  debounceTimers.set(key, setTimeout(() => {
    debounceTimers.delete(key);
    scanDocument(document);
  }, 500));
}

/**
 * Scan a single document and update diagnostics
 */
function scanDocument(document: vscode.TextDocument): void {
  const filePath = document.uri.fsPath;
  const content = document.getText();

  const violations = engine.scanFile(filePath, content);

  // Apply severity filter from settings
  const config = vscode.workspace.getConfiguration('halo');
  const minSeverity = config.get<string>('severity', 'all');
  const filtered = filterBySeverity(violations, minSeverity);

  // Convert violations to VS Code diagnostics
  const diagnostics = filtered.map(v => violationToDiagnostic(v, document));

  diagnosticCollection.set(document.uri, diagnostics);
}

/**
 * Filter violations by minimum severity
 */
function filterBySeverity(violations: Violation[], minSeverity: string): Violation[] {
  if (minSeverity === 'all') return violations;

  const levels: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
  const threshold = levels[minSeverity] || 0;

  return violations.filter(v => (levels[v.severity] || 0) >= threshold);
}

/**
 * Convert a Violation to a VS Code Diagnostic
 */
function violationToDiagnostic(violation: Violation, document: vscode.TextDocument): vscode.Diagnostic {
  const line = Math.max(0, violation.line - 1);
  const col = Math.max(0, violation.column - 1);

  // Try to highlight the whole relevant portion of the line
  const lineText = document.lineAt(line).text;
  const endCol = Math.min(lineText.length, col + 40);

  const range = new vscode.Range(line, col, line, endCol);
  const severity = severityToVscode(violation.severity);

  const diagnostic = new vscode.Diagnostic(range, violation.message, severity);
  diagnostic.code = {
    value: violation.ruleId,
    target: vscode.Uri.parse(`https://runhalo.dev/rules/${violation.ruleId}`)
  };
  diagnostic.source = DIAGNOSTIC_SOURCE;

  return diagnostic;
}

/**
 * Map severity to VS Code DiagnosticSeverity
 */
function severityToVscode(severity: string): vscode.DiagnosticSeverity {
  switch (severity) {
    case 'critical': return vscode.DiagnosticSeverity.Error;
    case 'high': return vscode.DiagnosticSeverity.Warning;
    case 'medium': return vscode.DiagnosticSeverity.Information;
    case 'low': return vscode.DiagnosticSeverity.Hint;
    default: return vscode.DiagnosticSeverity.Information;
  }
}

/**
 * Severity icon for quick pick
 */
function severityIcon(severity: string): string {
  switch (severity) {
    case 'critical': return '🔴';
    case 'high': return '🟠';
    case 'medium': return '🟡';
    case 'low': return '🔵';
    default: return '⚪';
  }
}

/**
 * Scan entire workspace
 */
async function scanWorkspace(): Promise<void> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders) {
    vscode.window.showWarningMessage('Halo: No workspace folder open');
    return;
  }

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'Halo: Scanning workspace...',
      cancellable: true
    },
    async (progress, token) => {
      const files = await vscode.workspace.findFiles(
        '**/*.{ts,js,tsx,jsx,py,swift,html,vue,svelte}',
        '{**/node_modules/**,**/dist/**,**/build/**,**/.git/**}'
      );

      let totalViolations = 0;
      const total = files.length;

      for (let i = 0; i < files.length; i++) {
        if (token.isCancellationRequested) break;

        progress.report({
          increment: (1 / total) * 100,
          message: `${i + 1}/${total} files`
        });

        try {
          const doc = await vscode.workspace.openTextDocument(files[i]);
          const content = doc.getText();
          const violations = engine.scanFile(files[i].fsPath, content);

          if (violations.length > 0) {
            totalViolations += violations.length;
            const diagnostics = violations.map(v => violationToDiagnostic(v, doc));
            diagnosticCollection.set(files[i], diagnostics);
          }
        } catch {
          // Skip files that can't be opened
        }
      }

      if (totalViolations > 0) {
        vscode.window.showWarningMessage(
          `Halo: Found ${totalViolations} COPPA violation(s) across ${total} files`
        );
      } else {
        vscode.window.showInformationMessage(
          `Halo: No COPPA violations found in ${total} files`
        );
      }
    }
  );
}

/**
 * Code Action Provider — Quick Fixes for COPPA violations
 */
class HaloCodeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== DIAGNOSTIC_SOURCE) continue;

      const ruleId = typeof diagnostic.code === 'object'
        ? (diagnostic.code as any).value
        : diagnostic.code;

      if (!ruleId) continue;

      // Add "Suppress with comment" action
      const suppressAction = new vscode.CodeAction(
        `Suppress ${ruleId} (add // halo-ignore)`,
        vscode.CodeActionKind.QuickFix
      );
      suppressAction.edit = new vscode.WorkspaceEdit();
      const line = diagnostic.range.start.line;
      const lineText = document.lineAt(line).text;
      suppressAction.edit.insert(
        document.uri,
        new vscode.Position(line, lineText.length),
        ` // halo-ignore: ${ruleId}`
      );
      suppressAction.diagnostics = [diagnostic];
      actions.push(suppressAction);

      // Add "Suppress next line" action
      const suppressLineAction = new vscode.CodeAction(
        `Suppress ${ruleId} (add comment above)`,
        vscode.CodeActionKind.QuickFix
      );
      suppressLineAction.edit = new vscode.WorkspaceEdit();
      const indent = lineText.match(/^\s*/)?.[0] || '';
      suppressLineAction.edit.insert(
        document.uri,
        new vscode.Position(line, 0),
        `${indent}// halo-ignore: ${ruleId}\n`
      );
      suppressLineAction.diagnostics = [diagnostic];
      actions.push(suppressLineAction);

      // Add "Explain rule" action
      const explainAction = new vscode.CodeAction(
        `Explain ${ruleId}`,
        vscode.CodeActionKind.QuickFix
      );
      explainAction.command = {
        command: 'halo.explainRule',
        title: 'Explain Rule',
        arguments: [ruleId]
      };
      explainAction.diagnostics = [diagnostic];
      actions.push(explainAction);
    }

    return actions;
  }
}

/**
 * Format rule explanation as HTML for webview
 */
function formatRuleExplanation(ruleId: string, explanation: string): string {
  const rule = COPPA_RULES.find(r => r.id === ruleId);
  const fix = engine.getFixSuggestion(ruleId);

  return `<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; padding: 20px; }
    h1 { color: #e74c3c; }
    .severity { display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: bold; }
    .critical { background: #e74c3c; color: white; }
    .high { background: #e67e22; color: white; }
    .medium { background: #f1c40f; color: black; }
    .low { background: #3498db; color: white; }
    pre { background: #1e1e1e; color: #d4d4d4; padding: 12px; border-radius: 6px; overflow-x: auto; }
    .section { margin: 16px 0; }
  </style>
</head>
<body>
  <h1>${ruleId}</h1>
  <h2>${rule?.name || 'Unknown Rule'}</h2>
  <span class="severity ${rule?.severity || ''}">${(rule?.severity || '').toUpperCase()}</span>

  <div class="section">
    <h3>Description</h3>
    <p>${rule?.description || explanation}</p>
  </div>

  <div class="section">
    <h3>Penalty</h3>
    <p>${rule?.penalty || 'N/A'}</p>
  </div>

  <div class="section">
    <h3>Fix Suggestion</h3>
    <pre>${escapeHtml(fix)}</pre>
  </div>

  <div class="section">
    <h3>Supported Languages</h3>
    <p>${rule?.languages.join(', ') || 'N/A'}</p>
  </div>
</body>
</html>`;
}

function escapeHtml(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/**
 * Update status bar with license tier
 */
function updateStatusBar(): void {
  if (!statusBarItem) return;

  const tierLabel = currentLicense.tier.charAt(0).toUpperCase() + currentLicense.tier.slice(1);
  const icon = currentLicense.tier === 'free' ? '$(shield)' : '$(verified)';
  statusBarItem.text = `${icon} Halo ${tierLabel}`;
  statusBarItem.tooltip = currentLicense.email
    ? `Halo ${tierLabel} — ${currentLicense.email}\nClick to manage license`
    : 'Halo Free — Click to activate license';
  statusBarItem.command = currentLicense.tier === 'free' ? 'halo.activate' : 'halo.deactivate';
}

/**
 * Deactivate the extension
 */
export function deactivate(): void {
  debounceTimers.forEach(timer => clearTimeout(timer));
  debounceTimers.clear();
  if (diagnosticCollection) {
    diagnosticCollection.clear();
    diagnosticCollection.dispose();
  }
}

/**
 * Minimal vscode module mock for unit testing
 */
export enum DiagnosticSeverity {
  Error = 0,
  Warning = 1,
  Information = 2,
  Hint = 3
}

export class Range {
  constructor(
    public startLine: number,
    public startChar: number,
    public endLine: number,
    public endChar: number
  ) {}

  get start() { return { line: this.startLine, character: this.startChar }; }
  get end() { return { line: this.endLine, character: this.endChar }; }
}

export class Position {
  constructor(public line: number, public character: number) {}
}

export class Diagnostic {
  code?: string | { value: string; target: any };
  source?: string;

  constructor(
    public range: Range,
    public message: string,
    public severity?: DiagnosticSeverity
  ) {}
}

export class Uri {
  static parse(value: string) { return { toString: () => value }; }
  static file(path: string) { return { fsPath: path, toString: () => path }; }
}

export const CodeActionKind = {
  QuickFix: 'quickfix'
};

export const workspace = {
  getConfiguration: () => ({
    get: (key: string, defaultValue: any) => defaultValue
  })
};

export const languages = {
  createDiagnosticCollection: () => ({
    set: () => {},
    delete: () => {},
    clear: () => {},
    dispose: () => {}
  }),
  registerCodeActionsProvider: () => ({ dispose: () => {} })
};

export const window = {
  activeTextEditor: null,
  visibleTextEditors: [],
  showInformationMessage: () => {},
  showWarningMessage: () => {},
  showQuickPick: () => Promise.resolve(null),
  createWebviewPanel: () => ({ webview: { html: '' } }),
  withProgress: () => Promise.resolve()
};

export const ProgressLocation = {
  Notification: 15
};

export const commands = {
  registerCommand: () => ({ dispose: () => {} })
};

export class WorkspaceEdit {
  insert() {}
}

/**
 * ImportGraphBuilder — Lightweight cross-file import tracking.
 *
 *  Builds an adjacency list of import/require relationships
 * for all scanned files. Zero API cost, ~50ms per repo.
 *
 * Used by:
 *   - AI Review Board: provides cross-file context for compliance analysis
 *   - CLI: shows import relationships in verbose mode
 *   - Future: dead code detection, dependency risk scoring
 *
 * Don't Go Backwards Rule: This is a pre-filter enrichment.
 * If it fails, scan continues without import context.
 */

export interface ImportEdge {
  /** The resolved or raw import path */
  source: string;
  /** Whether it's a relative import (./foo) or package import (firebase/auth) */
  isRelative: boolean;
  /** Whether it's a default import, named import, or side-effect import */
  kind: 'default' | 'named' | 'namespace' | 'side-effect' | 'require' | 'dynamic';
  /** Named imports if applicable (e.g., ['useState', 'useEffect']) */
  names?: string[];
}

export interface ImportGraph {
  /** Map of file path → list of imports from that file */
  edges: Record<string, ImportEdge[]>;
  /** Files that import a given module path (reverse lookup) */
  importedBy: Record<string, string[]>;
  /** Total number of files analyzed */
  fileCount: number;
  /** Total number of import edges */
  edgeCount: number;
  /** Build time in milliseconds */
  buildTimeMs: number;
}

export interface ImportGraphSummary {
  /** Top-level package imports (e.g., 'firebase/analytics', 'react', '@sentry/browser') */
  packageImports: string[];
  /** Files with the most imports (potential "hub" files) */
  hubFiles: { file: string; importCount: number }[];
  /** SDK-related imports for compliance context */
  complianceRelevantImports: { file: string; module: string; risk: string }[];
}

// Compliance-relevant package patterns
const COMPLIANCE_PACKAGES: Record<string, string> = {
  'firebase/analytics': 'analytics-tracking',
  'firebase/auth': 'authentication',
  '@google-analytics': 'analytics-tracking',
  'react-ga': 'analytics-tracking',
  'mixpanel': 'analytics-tracking',
  'amplitude': 'analytics-tracking',
  'segment': 'analytics-tracking',
  '@segment': 'analytics-tracking',
  'hotjar': 'session-recording',
  'fullstory': 'session-recording',
  '@sentry': 'error-tracking',
  'facebook-pixel': 'advertising',
  'react-facebook-pixel': 'advertising',
  '@stripe': 'payment-processing',
  'stripe': 'payment-processing',
  'braintree': 'payment-processing',
  'push-notification': 'push-notifications',
  'expo-notifications': 'push-notifications',
  '@react-native-firebase/messaging': 'push-notifications',
  'expo-location': 'geolocation',
  'react-native-geolocation': 'geolocation',
  '@capacitor/geolocation': 'geolocation',
  'socket.io': 'real-time-communication',
  'ws': 'real-time-communication',
  'face-api': 'biometric',
  'tensorflow': 'ai-ml',
  '@tensorflow': 'ai-ml',
  'openai': 'ai-ml',
  '@anthropic-ai': 'ai-ml',
};

/**
 * Extract imports from a single file's content.
 * Handles: ES6 import, CommonJS require, dynamic import().
 */
export function extractImports(content: string): ImportEdge[] {
  const imports: ImportEdge[] = [];

  // ES6 static imports
  // import X from 'module'
  // import { X, Y } from 'module'
  // import * as X from 'module'
  // import 'module' (side-effect)
  const es6Pattern = /import\s+(?:(?:(\{[^}]+\})|(\*\s+as\s+\w+)|(\w+))\s+from\s+)?['"]([^'"]+)['"]/g;
  let match: RegExpExecArray | null;

  while ((match = es6Pattern.exec(content)) !== null) {
    const namedPart = match[1]; // { X, Y }
    const namespacePart = match[2]; // * as X
    const defaultPart = match[3]; // X
    const modulePath = match[4];

    let kind: ImportEdge['kind'];
    let names: string[] | undefined;

    if (namedPart) {
      kind = 'named';
      names = namedPart
        .replace(/[{}]/g, '')
        .split(',')
        .map(n => n.trim().split(/\s+as\s+/)[0].trim())
        .filter(Boolean);
    } else if (namespacePart) {
      kind = 'namespace';
    } else if (defaultPart) {
      kind = 'default';
    } else {
      kind = 'side-effect';
    }

    imports.push({
      source: modulePath,
      isRelative: modulePath.startsWith('.') || modulePath.startsWith('/'),
      kind,
      names,
    });
  }

  // CommonJS require
  // const X = require('module')
  // require('module')
  const requirePattern = /(?:const|let|var)\s+(?:\{[^}]+\}|\w+)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)|(?:^|\s)require\s*\(\s*['"]([^'"]+)['"]\s*\)/gm;
  while ((match = requirePattern.exec(content)) !== null) {
    const modulePath = match[1] || match[2];
    if (modulePath) {
      imports.push({
        source: modulePath,
        isRelative: modulePath.startsWith('.') || modulePath.startsWith('/'),
        kind: 'require',
        names: undefined,
      });
    }
  }

  // Dynamic import()
  // import('module')
  const dynamicPattern = /import\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
  while ((match = dynamicPattern.exec(content)) !== null) {
    imports.push({
      source: match[1],
      isRelative: match[1].startsWith('.') || match[1].startsWith('/'),
      kind: 'dynamic',
      names: undefined,
    });
  }

  return imports;
}

/**
 * Build an import graph from a set of files.
 * @param files Map of file path → file content
 * @returns ImportGraph with forward and reverse edges
 */
export function buildImportGraph(files: Map<string, string>): ImportGraph {
  const start = Date.now();
  const edges: Record<string, ImportEdge[]> = {};
  const importedBy: Record<string, string[]> = {};
  let edgeCount = 0;

  for (const [filePath, content] of files) {
    const fileImports = extractImports(content);
    edges[filePath] = fileImports;
    edgeCount += fileImports.length;

    // Build reverse lookup
    for (const imp of fileImports) {
      if (!importedBy[imp.source]) {
        importedBy[imp.source] = [];
      }
      importedBy[imp.source].push(filePath);
    }
  }

  return {
    edges,
    importedBy,
    fileCount: files.size,
    edgeCount,
    buildTimeMs: Date.now() - start,
  };
}

/**
 * Generate a summary of the import graph for AI Review Board context.
 * Focuses on compliance-relevant imports and hub files.
 */
export function summarizeImportGraph(graph: ImportGraph): ImportGraphSummary {
  // Collect unique package imports
  const packageSet = new Set<string>();
  const complianceImports: ImportGraphSummary['complianceRelevantImports'] = [];

  for (const [filePath, fileImports] of Object.entries(graph.edges)) {
    for (const imp of fileImports) {
      if (!imp.isRelative) {
        packageSet.add(imp.source);

        // Check against compliance-relevant packages
        for (const [pattern, risk] of Object.entries(COMPLIANCE_PACKAGES)) {
          if (imp.source.startsWith(pattern) || imp.source === pattern) {
            complianceImports.push({
              file: filePath,
              module: imp.source,
              risk,
            });
          }
        }
      }
    }
  }

  // Find hub files (most imports)
  const hubFiles = Object.entries(graph.edges)
    .map(([file, imports]) => ({ file, importCount: imports.length }))
    .sort((a, b) => b.importCount - a.importCount)
    .slice(0, 10);

  // Deduplicate compliance imports
  const seen = new Set<string>();
  const uniqueComplianceImports = complianceImports.filter(ci => {
    const key = `${ci.file}:${ci.module}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return {
    packageImports: Array.from(packageSet).sort(),
    hubFiles,
    complianceRelevantImports: uniqueComplianceImports,
  };
}

/**
 * Format import graph summary for AI Review Board context.
 * Returns a compact string suitable for including in the AI prompt.
 */
export function formatImportGraphForReview(summary: ImportGraphSummary): string {
  const lines: string[] = ['## Import Graph Context'];

  if (summary.complianceRelevantImports.length > 0) {
    lines.push('\n### Compliance-Relevant Dependencies');
    const byRisk = new Map<string, string[]>();
    for (const ci of summary.complianceRelevantImports) {
      if (!byRisk.has(ci.risk)) byRisk.set(ci.risk, []);
      byRisk.get(ci.risk)!.push(`${ci.module} (${ci.file})`);
    }
    for (const [risk, modules] of byRisk) {
      lines.push(`- **${risk}**: ${modules.join(', ')}`);
    }
  }

  if (summary.hubFiles.length > 0) {
    lines.push('\n### Hub Files (most imports)');
    for (const hub of summary.hubFiles.slice(0, 5)) {
      lines.push(`- ${hub.file}: ${hub.importCount} imports`);
    }
  }

  if (summary.packageImports.length > 0) {
    lines.push(`\n### Package Dependencies (${summary.packageImports.length} total)`);
    // Only list first 20 to keep context compact
    const listed = summary.packageImports.slice(0, 20);
    lines.push(listed.join(', '));
    if (summary.packageImports.length > 20) {
      lines.push(`... and ${summary.packageImports.length - 20} more`);
    }
  }

  return lines.join('\n');
}

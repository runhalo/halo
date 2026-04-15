import {
  extractImports,
  buildImportGraph,
  summarizeImportGraph,
  formatImportGraphForReview,
  ImportEdge,
} from '../import-graph';

describe('ImportGraphBuilder', () => {
  describe('extractImports', () => {
    it('extracts ES6 default imports', () => {
      const content = `import React from 'react';\nimport App from './App';`;
      const imports = extractImports(content);
      expect(imports).toEqual(expect.arrayContaining([
        expect.objectContaining({ source: 'react', kind: 'default', isRelative: false }),
        expect.objectContaining({ source: './App', kind: 'default', isRelative: true }),
      ]));
    });

    it('extracts ES6 named imports', () => {
      const content = `import { useState, useEffect } from 'react';`;
      const imports = extractImports(content);
      expect(imports).toHaveLength(1);
      expect(imports[0].kind).toBe('named');
      expect(imports[0].names).toEqual(['useState', 'useEffect']);
    });

    it('extracts namespace imports', () => {
      const content = `import * as path from 'path';`;
      const imports = extractImports(content);
      expect(imports).toHaveLength(1);
      expect(imports[0].kind).toBe('namespace');
      expect(imports[0].source).toBe('path');
    });

    it('extracts side-effect imports', () => {
      const content = `import './styles.css';`;
      const imports = extractImports(content);
      expect(imports).toHaveLength(1);
      expect(imports[0].kind).toBe('side-effect');
      expect(imports[0].isRelative).toBe(true);
    });

    it('extracts CommonJS require', () => {
      const content = `const fs = require('fs');\nconst { join } = require('path');`;
      const imports = extractImports(content);
      const requireImports = imports.filter(i => i.kind === 'require');
      expect(requireImports.length).toBeGreaterThanOrEqual(2);
      expect(requireImports).toEqual(expect.arrayContaining([
        expect.objectContaining({ source: 'fs', kind: 'require' }),
        expect.objectContaining({ source: 'path', kind: 'require' }),
      ]));
    });

    it('extracts dynamic imports', () => {
      const content = `const module = await import('./lazy-module');`;
      const imports = extractImports(content);
      expect(imports).toEqual(expect.arrayContaining([
        expect.objectContaining({ source: './lazy-module', kind: 'dynamic', isRelative: true }),
      ]));
    });

    it('handles aliased named imports', () => {
      const content = `import { useState as state, useEffect as effect } from 'react';`;
      const imports = extractImports(content);
      expect(imports[0].names).toEqual(['useState', 'useEffect']);
    });

    it('handles scoped package imports', () => {
      const content = `import { getAnalytics } from '@firebase/analytics';`;
      const imports = extractImports(content);
      expect(imports[0].source).toBe('@firebase/analytics');
      expect(imports[0].isRelative).toBe(false);
    });

    it('returns empty array for files with no imports', () => {
      const content = `const x = 42;\nfunction hello() { return 'world'; }`;
      const imports = extractImports(content);
      expect(imports).toHaveLength(0);
    });

    it('handles mixed import styles', () => {
      const content = `
import React from 'react';
import { useState } from 'react';
const path = require('path');
import('./dynamic-module');
import 'side-effect';
      `;
      const imports = extractImports(content);
      expect(imports.length).toBeGreaterThanOrEqual(5);
    });
  });

  describe('buildImportGraph', () => {
    it('builds forward edges from file map', () => {
      const files = new Map<string, string>([
        ['src/index.ts', `import { App } from './App';\nimport React from 'react';`],
        ['src/App.ts', `import { Button } from './Button';`],
        ['src/Button.ts', `import React from 'react';`],
      ]);

      const graph = buildImportGraph(files);
      expect(graph.fileCount).toBe(3);
      expect(graph.edgeCount).toBe(4);
      expect(graph.edges['src/index.ts']).toHaveLength(2);
      expect(graph.edges['src/App.ts']).toHaveLength(1);
      expect(graph.edges['src/Button.ts']).toHaveLength(1);
    });

    it('builds reverse edges (importedBy)', () => {
      const files = new Map<string, string>([
        ['src/a.ts', `import React from 'react';`],
        ['src/b.ts', `import React from 'react';`],
      ]);

      const graph = buildImportGraph(files);
      expect(graph.importedBy['react']).toEqual(['src/a.ts', 'src/b.ts']);
    });

    it('handles empty file map', () => {
      const graph = buildImportGraph(new Map());
      expect(graph.fileCount).toBe(0);
      expect(graph.edgeCount).toBe(0);
    });

    it('records build time', () => {
      const files = new Map<string, string>([
        ['src/a.ts', `import React from 'react';`],
      ]);
      const graph = buildImportGraph(files);
      expect(typeof graph.buildTimeMs).toBe('number');
      expect(graph.buildTimeMs).toBeGreaterThanOrEqual(0);
    });
  });

  describe('summarizeImportGraph', () => {
    it('identifies compliance-relevant imports', () => {
      const files = new Map<string, string>([
        ['src/analytics.ts', `import { getAnalytics } from 'firebase/analytics';`],
        ['src/auth.ts', `import { getAuth } from 'firebase/auth';`],
        ['src/payments.ts', `import Stripe from 'stripe';`],
      ]);

      const graph = buildImportGraph(files);
      const summary = summarizeImportGraph(graph);

      expect(summary.complianceRelevantImports).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ module: 'firebase/analytics', risk: 'analytics-tracking' }),
          expect.objectContaining({ module: 'firebase/auth', risk: 'authentication' }),
          expect.objectContaining({ module: 'stripe', risk: 'payment-processing' }),
        ])
      );
    });

    it('ranks hub files by import count', () => {
      const files = new Map<string, string>([
        ['src/index.ts', `import a from 'a';\nimport b from 'b';\nimport c from 'c';`],
        ['src/small.ts', `import a from 'a';`],
      ]);

      const graph = buildImportGraph(files);
      const summary = summarizeImportGraph(graph);

      expect(summary.hubFiles[0].file).toBe('src/index.ts');
      expect(summary.hubFiles[0].importCount).toBe(3);
    });

    it('collects unique package imports', () => {
      const files = new Map<string, string>([
        ['src/a.ts', `import React from 'react';\nimport { useState } from 'react';`],
        ['src/b.ts', `import React from 'react';`],
      ]);

      const graph = buildImportGraph(files);
      const summary = summarizeImportGraph(graph);

      // 'react' should appear only once
      const reactCount = summary.packageImports.filter(p => p === 'react').length;
      expect(reactCount).toBe(1);
    });
  });

  describe('formatImportGraphForReview', () => {
    it('returns markdown format', () => {
      const files = new Map<string, string>([
        ['src/track.ts', `import { getAnalytics } from 'firebase/analytics';`],
      ]);
      const graph = buildImportGraph(files);
      const summary = summarizeImportGraph(graph);
      const output = formatImportGraphForReview(summary);

      expect(output).toContain('## Import Graph Context');
      expect(output).toContain('analytics-tracking');
      expect(output).toContain('firebase/analytics');
    });

    it('handles empty graph gracefully', () => {
      const graph = buildImportGraph(new Map());
      const summary = summarizeImportGraph(graph);
      const output = formatImportGraphForReview(summary);

      expect(output).toContain('## Import Graph Context');
      // Should not throw, should be a minimal output
    });
  });
});

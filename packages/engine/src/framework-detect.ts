/**
 * Framework Detection — detects project framework from package.json
 * Used by ScaffoldEngine to generate framework-specific code scaffolds
 */

import * as fs from 'fs';
import * as path from 'path';

export type Framework = 'react' | 'nextjs' | 'vue' | 'svelte' | 'plain-js';

export interface FrameworkDetectionResult {
  framework: Framework;
  typescript: boolean;
  confidence: number; // 0-1
}

/**
 * Detect the project framework by reading package.json
 * Priority: next > react > vue > svelte > plain-js
 */
export function detectFramework(projectPath: string): FrameworkDetectionResult {
  const result: FrameworkDetectionResult = {
    framework: 'plain-js',
    typescript: false,
    confidence: 0.3,
  };

  // Try to read package.json
  const pkgPath = path.join(projectPath, 'package.json');
  let pkg: any = null;

  try {
    if (fs.existsSync(pkgPath)) {
      pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
    }
  } catch {
    // Malformed package.json — fall through to defaults
  }

  if (!pkg) {
    // Check for tsconfig.json even without package.json
    const tsconfigPath = path.join(projectPath, 'tsconfig.json');
    if (fs.existsSync(tsconfigPath)) {
      result.typescript = true;
    }
    return result;
  }

  const deps = pkg.dependencies || {};
  const devDeps = pkg.devDependencies || {};
  const allDeps = { ...deps, ...devDeps };

  // Detect TypeScript
  if (allDeps['typescript']) {
    result.typescript = true;
  } else {
    const tsconfigPath = path.join(projectPath, 'tsconfig.json');
    if (fs.existsSync(tsconfigPath)) {
      result.typescript = true;
    }
  }

  // Detect framework (priority order — Next.js includes React, so check first)
  if (deps['next'] || devDeps['next']) {
    result.framework = 'nextjs';
    result.confidence = 0.95;
  } else if (deps['react'] || devDeps['react']) {
    result.framework = 'react';
    result.confidence = 0.9;
  } else if (deps['vue'] || devDeps['vue']) {
    result.framework = 'vue';
    result.confidence = 0.9;
  } else if (deps['svelte'] || devDeps['svelte']) {
    result.framework = 'svelte';
    result.confidence = 0.9;
  } else {
    result.framework = 'plain-js';
    result.confidence = 0.5;
  }

  return result;
}

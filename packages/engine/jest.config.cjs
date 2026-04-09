module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/__tests__/**/*.test.ts'],
  testPathIgnorePatterns: ['/node_modules/', '/dist/'],
  modulePathIgnorePatterns: ['<rootDir>/src/__tests__/fixtures/'],
  // Each test file gets its own forked process to avoid tree-sitter
  // native module conflicts (C++ binding corruption in shared worker threads).
  // workerThreads: false forces child_process forks instead of worker_threads,
  // giving each test file truly isolated native module state.
  workerThreads: false,
  maxWorkers: '100%',
  workerIdleMemoryLimit: '256MB',
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      tsconfig: {
        module: 'commonjs',
        esModuleInterop: true,
        allowSyntheticDefaultImports: true,
        target: 'ES2020'
      },
      isolatedModules: true
    }]
  }
};

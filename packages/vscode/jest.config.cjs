module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/__tests__/**/*.test.ts'],
  testPathIgnorePatterns: ['/node_modules/', '/dist/'],
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
  },
  // Mock vscode module since we can't import it in unit tests
  moduleNameMapper: {
    '^vscode$': '<rootDir>/src/__tests__/vscode-mock.ts'
  }
};

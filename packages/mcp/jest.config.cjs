module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/__tests__/**/*.test.ts'],
  testPathIgnorePatterns: ['/node_modules/', '/dist/'],
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      tsconfig: {
        module: 'ES2020',
        esModuleInterop: true,
        allowSyntheticDefaultImports: true,
        target: 'ES2020'
      },
      isolatedModules: true
    }]
  }
};

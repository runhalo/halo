module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/packages/engine/src/**/*.test.ts'],
  testPathIgnorePatterns: ['/node_modules/', '/dist/'],
  moduleNameMapper: {
    '^@runhalo/engine$': '<rootDir>/packages/engine/src/index.ts'
  },
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      tsconfig: '<rootDir>/packages/engine/tsconfig.test.json',
      isolatedModules: true
    }]
  }
};

import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['test/**/*.ts'],
    // test/typecheck/** is compile-time-only (tsconfig.typecheck.json /
    // `yarn test:types`); it has no runtime assertions, so keep vitest
    // from collecting it as an empty/failing suite.
    exclude: ['node_modules', 'build', 'test/typecheck/**'],
    globals: true,
    environment: 'node',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'json-summary'],
      include: ['src/**/*.ts', 'index.ts'],
      exclude: ['build', 'types', 'test'],
      thresholds: {
        statements: 90,
        branches: 90,
        functions: 90,
        lines: 90,
      },
    },
  },
})

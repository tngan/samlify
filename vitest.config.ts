import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['test/**/*.ts'],
    exclude: ['node_modules', 'build'],
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

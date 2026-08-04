import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    // Integration tests share one Postgres schema; running files in parallel
    // would have them truncating each other's rows.
    fileParallelism: false,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.ts'],
  },
})

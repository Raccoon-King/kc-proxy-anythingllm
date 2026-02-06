import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  fullyParallel: false, // Auth flows need sequential execution
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: process.env.CI
    ? [['junit', { outputFile: 'test-results/junit.xml' }], ['html']]
    : 'html',

  use: {
    baseURL: process.env.PROXY_URL || 'http://localhost:8080',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'on-first-retry',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  // Global timeout for tests
  timeout: 60000,

  // Expect timeout
  expect: {
    timeout: 10000,
  },
});

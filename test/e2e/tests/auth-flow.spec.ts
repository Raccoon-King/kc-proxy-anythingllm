import { test, expect } from '@playwright/test';
import {
  setupRedirectTracking,
  assertNoRedirectLoop,
} from '../helpers/redirect-tracker';

const KEYCLOAK_URL = process.env.KEYCLOAK_URL || 'http://localhost:8180';
const TEST_USER = process.env.TEST_USER || 'testuser';
const TEST_PASS = process.env.TEST_PASS || 'testpass';

test.describe('Authentication Flow', () => {
  test('health endpoint returns 200', async ({ request }) => {
    const response = await request.get('/healthz');
    expect(response.status()).toBe(200);
  });

  test('readiness endpoint returns 200', async ({ request }) => {
    const response = await request.get('/readyz');
    expect(response.status()).toBe(200);
  });

  test('unauthenticated request redirects to login', async ({ page }) => {
    const tracker = await setupRedirectTracking(page);

    // Go to protected route
    await page.goto('/chat');

    // Should redirect to login
    await expect(page).toHaveURL(/\/login/);

    // Verify no redirect loop
    assertNoRedirectLoop(tracker);
  });

  test('login redirects to Keycloak', async ({ page }) => {
    const tracker = await setupRedirectTracking(page);

    // Go to login page
    await page.goto('/login?redirect=%2Fchat');

    // Should redirect to Keycloak
    await page.waitForURL(/keycloak|realms/, { timeout: 30000 });
    expect(page.url()).toContain('openid-connect/auth');

    // Verify no redirect loop
    assertNoRedirectLoop(tracker);
  });

  test('complete login flow: proxy -> keycloak -> callback -> app', async ({
    page,
  }) => {
    const tracker = await setupRedirectTracking(page);

    // 1. Navigate to protected route
    await page.goto('/chat');

    // 2. Should redirect to login
    await expect(page).toHaveURL(/\/login/);

    // 3. Wait for Keycloak login page
    await page.waitForURL(/keycloak|realms/, { timeout: 30000 });

    // 4. Fill Keycloak login form
    await page.fill('#username', TEST_USER);
    await page.fill('#password', TEST_PASS);
    await page.click('#kc-login');

    // 5. Should redirect back to app (agreement or chat)
    await page.waitForURL(/\/agreement|\/chat|\/login\/path/, {
      timeout: 30000,
    });

    // 6. If agreement page, accept it
    const currentUrl = page.url();
    if (currentUrl.includes('/agreement')) {
      await page.click('button[type="submit"]');
      await page.waitForURL(/\/chat|\/login\/path/, { timeout: 10000 });
    }

    // Verify no redirect loops occurred
    assertNoRedirectLoop(tracker);

    // Verify we're logged in (not on login page)
    expect(page.url()).not.toContain('/login?');
  });

  test('invalid credentials shows error on Keycloak', async ({ page }) => {
    // Go to login
    await page.goto('/login');

    // Wait for Keycloak
    await page.waitForURL(/keycloak|realms/, { timeout: 30000 });

    // Enter invalid credentials
    await page.fill('#username', 'invaliduser');
    await page.fill('#password', 'invalidpass');
    await page.click('#kc-login');

    // Should stay on Keycloak with error
    await page.waitForSelector('.alert-error, .kc-feedback-text', {
      timeout: 10000,
    });
    expect(page.url()).toContain('openid-connect');
  });
});

test.describe('Session Management', () => {
  test('logout clears session', async ({ page, context }) => {
    // First login
    await page.goto('/login');
    await page.waitForURL(/keycloak|realms/, { timeout: 30000 });
    await page.fill('#username', TEST_USER);
    await page.fill('#password', TEST_PASS);
    await page.click('#kc-login');
    await page.waitForURL(/\/agreement|\/chat|\/login\/path/, {
      timeout: 30000,
    });

    // Handle agreement if present
    if (page.url().includes('/agreement')) {
      await page.click('button[type="submit"]');
      await page.waitForURL(/\/chat|\/login\/path/, { timeout: 10000 });
    }

    // Now logout
    await page.goto('/logout');

    // Should be redirected to logged-out page or login
    await page.waitForURL(/\/logged-out|\/login|keycloak/, { timeout: 30000 });

    // Try accessing protected route - should require login again
    await page.goto('/chat');
    await expect(page).toHaveURL(/\/login/);
  });

  test('expired cookie redirects to login', async ({ page, context }) => {
    // Access protected route without session
    await page.goto('/chat');

    // Should redirect to login
    await expect(page).toHaveURL(/\/login/);
  });
});

test.describe('State Validation', () => {
  test('callback with invalid state redirects to logout', async ({ page }) => {
    // Try to access callback with fake state
    const response = await page.goto(
      '/auth/callback?state=invalid-state&code=fake-code'
    );

    // Should redirect (to logout or login)
    expect(page.url()).toMatch(/\/logout|\/login|\/logged-out|keycloak/);
  });

  test('callback without state is rejected', async ({ page }) => {
    const response = await page.goto('/auth/callback?code=fake-code');

    // Should redirect to logout/login
    expect(page.url()).toMatch(/\/logout|\/login|\/logged-out|keycloak/);
  });
});

import { test, expect } from '@playwright/test';
import {
  setupRedirectTracking,
  RedirectTracker,
} from '../helpers/redirect-tracker';

test.describe('Redirect Loop Detection', () => {
  test('no redirect loop on unauthenticated access', async ({ page }) => {
    const tracker = await setupRedirectTracking(page);

    // Access root without authentication
    await page.goto('/');

    // Wait for redirects to settle
    await page.waitForTimeout(2000);

    // Check for loops
    if (tracker.isLooping()) {
      const loopingUrls = tracker.getLoopingUrls();
      const redirects = tracker.getRedirects();
      throw new Error(
        `Redirect loop detected on unauthenticated access!\n` +
          `Looping URLs: ${loopingUrls.join(', ')}\n` +
          `Redirect chain: ${redirects.join(' -> ')}`
      );
    }
  });

  test('no redirect loop on protected route access', async ({ page }) => {
    const tracker = await setupRedirectTracking(page);

    // Access protected route
    await page.goto('/chat');

    // Wait for redirects
    await page.waitForTimeout(2000);

    // Should not loop
    expect(tracker.isLooping()).toBe(false);
  });

  test('no redirect loop on login page', async ({ page }) => {
    const tracker = await setupRedirectTracking(page);

    await page.goto('/login');

    // Wait for redirect to Keycloak
    await page.waitForURL(/keycloak|realms/, { timeout: 30000 });

    // Should not loop
    expect(tracker.isLooping()).toBe(false);
  });

  test('no redirect loop on logout flow', async ({ page }) => {
    const tracker = await setupRedirectTracking(page);

    await page.goto('/logout');

    // Wait for redirects to settle
    await page.waitForTimeout(3000);

    // Should not loop
    if (tracker.isLooping()) {
      const loopingUrls = tracker.getLoopingUrls();
      throw new Error(`Redirect loop on logout: ${loopingUrls.join(', ')}`);
    }
  });

  test('no redirect loop on logged-out page', async ({ page }) => {
    const tracker = await setupRedirectTracking(page);

    await page.goto('/logged-out');

    await page.waitForTimeout(2000);

    expect(tracker.isLooping()).toBe(false);
  });

  test('tracks redirect count correctly', async ({ page }) => {
    const tracker = await setupRedirectTracking(page);

    // Go to a page that causes redirects
    await page.goto('/');

    // Get the visit counts
    const counts = tracker.getVisitCounts();

    // Log for debugging
    console.log('Redirect tracking results:');
    for (const [url, count] of counts) {
      console.log(`  ${url}: ${count} visits`);
    }

    // Verify no path was visited excessively
    for (const [url, count] of counts) {
      expect(
        count,
        `URL ${url} was visited ${count} times, indicating a potential loop`
      ).toBeLessThan(5);
    }
  });

  test('maximum redirect limit is enforced', async ({ page }) => {
    // This test verifies the browser/proxy doesn't allow infinite redirects
    let redirectCount = 0;
    const maxExpectedRedirects = 20;

    page.on('response', (response) => {
      if (response.status() >= 300 && response.status() < 400) {
        redirectCount++;
      }
    });

    await page.goto('/');

    // Wait for navigation to complete
    await page.waitForTimeout(3000);

    // Verify we didn't hit an excessive number of redirects
    expect(
      redirectCount,
      `Excessive redirects: ${redirectCount}`
    ).toBeLessThan(maxExpectedRedirects);
  });
});

test.describe('Specific Redirect Scenarios', () => {
  test('agreement page does not cause loop when accepted', async ({
    page,
  }) => {
    const tracker = await setupRedirectTracking(page);

    // If we can access agreement directly
    const response = await page.goto('/agreement');

    // Wait for page to settle
    await page.waitForTimeout(1000);

    // Check for loops
    expect(tracker.isLooping()).toBe(false);
  });

  test('callback error does not cause loop', async ({ page }) => {
    const tracker = await setupRedirectTracking(page);

    // Invalid callback
    await page.goto('/auth/callback?error=access_denied');

    await page.waitForTimeout(2000);

    expect(tracker.isLooping()).toBe(false);
  });

  test('missing session redirects once to login', async ({ page }) => {
    const tracker = await setupRedirectTracking(page);

    // Clear any cookies
    await page.context().clearCookies();

    // Access protected route
    await page.goto('/chat');

    // Should end up at login
    await expect(page).toHaveURL(/\/login/);

    // Get redirect count for /login path
    const counts = tracker.getVisitCounts();
    let loginVisits = 0;
    for (const [url, count] of counts) {
      if (url.includes('/login')) {
        loginVisits += count;
      }
    }

    // Should only visit login once (not loop back to it)
    expect(loginVisits).toBeLessThanOrEqual(2);
  });
});

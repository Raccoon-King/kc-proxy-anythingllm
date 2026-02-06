import { Page } from '@playwright/test';

/**
 * RedirectTracker monitors page navigation and redirect responses
 * to detect redirect loops that could indicate configuration issues.
 */
export class RedirectTracker {
  private visitedUrls: Map<string, number> = new Map();
  private redirectResponses: string[] = [];
  private readonly maxVisits: number;

  constructor(maxVisits: number = 3) {
    this.maxVisits = maxVisits;
  }

  /**
   * Track a URL visit (either from navigation or redirect response)
   */
  trackUrl(url: string): void {
    // Normalize URL - use pathname + host for comparison
    try {
      const parsed = new URL(url);
      const normalizedUrl = `${parsed.host}${parsed.pathname}`;
      const count = (this.visitedUrls.get(normalizedUrl) || 0) + 1;
      this.visitedUrls.set(normalizedUrl, count);
    } catch {
      // If URL parsing fails, track as-is
      const count = (this.visitedUrls.get(url) || 0) + 1;
      this.visitedUrls.set(url, count);
    }
  }

  /**
   * Track redirect response
   */
  trackRedirect(url: string): void {
    this.redirectResponses.push(url);
    this.trackUrl(url);
  }

  /**
   * Check if a redirect loop has been detected
   */
  isLooping(): boolean {
    for (const [, count] of this.visitedUrls) {
      if (count >= this.maxVisits) {
        return true;
      }
    }
    return false;
  }

  /**
   * Get URLs that indicate a loop (visited >= maxVisits times)
   */
  getLoopingUrls(): string[] {
    return Array.from(this.visitedUrls.entries())
      .filter(([, count]) => count >= this.maxVisits)
      .map(([url]) => url);
  }

  /**
   * Get all redirect responses tracked
   */
  getRedirects(): string[] {
    return [...this.redirectResponses];
  }

  /**
   * Get visit counts for all URLs
   */
  getVisitCounts(): Map<string, number> {
    return new Map(this.visitedUrls);
  }

  /**
   * Reset tracking state
   */
  reset(): void {
    this.visitedUrls.clear();
    this.redirectResponses.length = 0;
  }
}

/**
 * Sets up redirect tracking on a Playwright page.
 * Tracks both redirect responses (3xx) and frame navigations.
 */
export async function setupRedirectTracking(page: Page): Promise<RedirectTracker> {
  const tracker = new RedirectTracker();

  // Track redirect responses
  page.on('response', (response) => {
    const status = response.status();
    if (status >= 300 && status < 400) {
      tracker.trackRedirect(response.url());
    }
  });

  // Track frame navigations
  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame()) {
      tracker.trackUrl(frame.url());
    }
  });

  return tracker;
}

/**
 * Asserts that no redirect loop was detected.
 * Throws an error with details if a loop is found.
 */
export function assertNoRedirectLoop(tracker: RedirectTracker): void {
  if (tracker.isLooping()) {
    const loopingUrls = tracker.getLoopingUrls();
    const allRedirects = tracker.getRedirects();
    throw new Error(
      `Redirect loop detected!\n` +
        `Looping URLs: ${loopingUrls.join(', ')}\n` +
        `All redirects: ${allRedirects.join(' -> ')}`
    );
  }
}

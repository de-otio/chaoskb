/**
 * Headless-browser fallback for JavaScript-rendered pages.
 *
 * When `extractContent` throws `JsRenderRequiredError`, the content pipeline
 * calls `fetchUrlWithBrowser` to re-fetch the URL through a Chromium instance
 * that executes the page's JavaScript, then feeds the rendered HTML back into
 * the normal extraction path.
 *
 * A module-level singleton Browser is launched lazily on first use and
 * self-closes after `IDLE_SHUTDOWN_MS` of inactivity, amortizing the 2–5 s
 * cold start across sequential ingestions while releasing the Chromium
 * subprocess (~200 MB resident) when the fallback isn't active.
 */

import { chromium, type Browser } from 'playwright';
import { MAX_RESPONSE_BYTES, validateUrl } from './fetch.js';

const IDLE_SHUTDOWN_MS = 60_000;
const NAV_TIMEOUT_MS = 15_000;

let browserPromise: Promise<Browser> | null = null;
let idleTimer: NodeJS.Timeout | null = null;

async function getBrowser(): Promise<Browser> {
  if (!browserPromise) {
    browserPromise = chromium.launch({ headless: true });
  }
  return browserPromise;
}

function scheduleIdleShutdown(): void {
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = setTimeout(async () => {
    const p = browserPromise;
    browserPromise = null;
    idleTimer = null;
    try {
      const browser = await p;
      await browser?.close();
    } catch {
      // Best-effort shutdown; swallow errors from a browser that already exited.
    }
  }, IDLE_SHUTDOWN_MS);
  idleTimer.unref();
}

/**
 * Fetch a URL through a headless Chromium instance, executing JavaScript and
 * returning the post-render HTML.
 *
 * @param url - The URL to render. SSRF-validated before the browser launch.
 * @returns The fully rendered HTML as a string.
 * @throws If SSRF validation fails, navigation times out, or the rendered
 *   HTML exceeds `MAX_RESPONSE_BYTES`.
 */
export async function fetchUrlWithBrowser(url: string): Promise<string> {
  // SSRF: validateUrl covers scheme, blocked hostnames, IP-literal private-IP
  // check, DNS resolution, and per-resolved-address private-IP rejection.
  await validateUrl(url);

  const browser = await getBrowser();
  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    try {
      await page.goto(url, { waitUntil: 'networkidle', timeout: NAV_TIMEOUT_MS });
    } catch {
      // Some sites never go fully idle (long-polling, analytics beacons).
      // Fall back to domcontentloaded so we still capture the rendered DOM.
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: NAV_TIMEOUT_MS });
    }
    const html = await page.content();
    if (html.length > MAX_RESPONSE_BYTES) {
      throw new Error(
        `Rendered page exceeds ${MAX_RESPONSE_BYTES / 1024 / 1024} MB limit.`,
      );
    }
    return html;
  } finally {
    await context.close();
    scheduleIdleShutdown();
  }
}

/**
 * Testing hook: tear down the singleton browser and cancel any pending idle
 * shutdown. Not called from production code.
 */
export async function _resetBrowserSingletonForTests(): Promise<void> {
  if (idleTimer) {
    clearTimeout(idleTimer);
    idleTimer = null;
  }
  const p = browserPromise;
  browserPromise = null;
  try {
    const browser = await p;
    await browser?.close();
  } catch {
    // ignore
  }
}

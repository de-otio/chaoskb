/**
 * Unit tests for fetch-browser.ts.
 *
 * Playwright's `chromium` is mocked so these tests don't require a running
 * Chromium binary and can assert singleton/idle/SSRF/size-cap behavior
 * independently of real browser launches.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const launchMock = vi.fn();

vi.mock('playwright', () => ({
  chromium: { launch: launchMock },
}));

type FakeBrowser = {
  close: ReturnType<typeof vi.fn>;
  newContext: ReturnType<typeof vi.fn>;
};

type FakePage = {
  goto: ReturnType<typeof vi.fn>;
  content: ReturnType<typeof vi.fn>;
};

type FakeContext = {
  close: ReturnType<typeof vi.fn>;
  newPage: ReturnType<typeof vi.fn>;
};

function makeFakeBrowser(
  opts: { pageHtml?: string } = {},
): FakeBrowser {
  const browser: FakeBrowser = {
    close: vi.fn(async () => undefined),
    // Fresh page + context per newContext() call so per-call close() assertions
    // aren't conflated across invocations.
    newContext: vi.fn(async () => {
      const page: FakePage = {
        goto: vi.fn(async () => undefined),
        content: vi.fn(async () => opts.pageHtml ?? '<html><body>ok</body></html>'),
      };
      const context: FakeContext = {
        close: vi.fn(async () => undefined),
        newPage: vi.fn(async () => page),
      };
      return context;
    }),
  };
  return browser;
}

async function loadFreshModule() {
  vi.resetModules();
  return await import('../fetch-browser.js');
}

describe('fetchUrlWithBrowser', () => {
  beforeEach(() => {
    launchMock.mockReset();
    vi.useRealTimers();
  });

  afterEach(async () => {
    // Drain any lingering singleton across tests.
    const mod = await import('../fetch-browser.js');
    await mod._resetBrowserSingletonForTests();
  });

  it('rejects private/internal URLs via SSRF check before launching a browser', async () => {
    const { fetchUrlWithBrowser } = await loadFreshModule();

    launchMock.mockImplementation(() => {
      throw new Error('should not launch');
    });

    await expect(
      fetchUrlWithBrowser('http://169.254.169.254/latest/meta-data/'),
    ).rejects.toThrow(/private\/internal/i);
    expect(launchMock).not.toHaveBeenCalled();
  });

  it('rejects non-http(s) schemes before launching a browser', async () => {
    const { fetchUrlWithBrowser } = await loadFreshModule();
    launchMock.mockImplementation(() => {
      throw new Error('should not launch');
    });

    await expect(fetchUrlWithBrowser('file:///etc/passwd')).rejects.toThrow(
      /not allowed/i,
    );
    expect(launchMock).not.toHaveBeenCalled();
  });

  it('reuses a single Browser instance across sequential calls', async () => {
    const { fetchUrlWithBrowser } = await loadFreshModule();
    const browser = makeFakeBrowser();
    launchMock.mockResolvedValue(browser);

    await fetchUrlWithBrowser('https://example.com/a');
    await fetchUrlWithBrowser('https://example.com/b');

    expect(launchMock).toHaveBeenCalledTimes(1);
    expect(browser.newContext).toHaveBeenCalledTimes(2);
  });

  it('creates a fresh BrowserContext per call and closes it in finally', async () => {
    const { fetchUrlWithBrowser } = await loadFreshModule();
    const browser = makeFakeBrowser();
    launchMock.mockResolvedValue(browser);

    await fetchUrlWithBrowser('https://example.com/a');
    await fetchUrlWithBrowser('https://example.com/b');

    expect(browser.newContext).toHaveBeenCalledTimes(2);
    // Each newContext's returned fake context should have had close() called.
    const ctx1 = await browser.newContext.mock.results[0].value;
    const ctx2 = await browser.newContext.mock.results[1].value;
    expect(ctx1.close).toHaveBeenCalledTimes(1);
    expect(ctx2.close).toHaveBeenCalledTimes(1);
  });

  it('throws when rendered HTML exceeds the 10 MB cap and still closes context', async () => {
    const { fetchUrlWithBrowser } = await loadFreshModule();
    const tooBig = 'a'.repeat(10 * 1024 * 1024 + 1);
    const browser = makeFakeBrowser({ pageHtml: tooBig });
    launchMock.mockResolvedValue(browser);

    await expect(fetchUrlWithBrowser('https://example.com/huge')).rejects.toThrow(
      /exceeds 10 MB limit/i,
    );
    const ctx = await browser.newContext.mock.results[0].value;
    expect(ctx.close).toHaveBeenCalledTimes(1);
  });

  it('falls back to domcontentloaded when networkidle navigation throws', async () => {
    const { fetchUrlWithBrowser } = await loadFreshModule();
    const browser = makeFakeBrowser();
    launchMock.mockResolvedValue(browser);

    // Stub goto so the first (networkidle) call rejects and the second
    // (domcontentloaded) resolves.
    const origNewContext = browser.newContext.getMockImplementation()!;
    browser.newContext.mockImplementationOnce(async () => {
      const ctx = await origNewContext();
      const page: FakePage = {
        goto: vi
          .fn()
          .mockRejectedValueOnce(new Error('networkidle timed out'))
          .mockResolvedValueOnce(undefined),
        content: vi.fn(async () => '<html><body>late</body></html>'),
      };
      ctx.newPage = vi.fn(async () => page);
      return ctx;
    });

    const html = await fetchUrlWithBrowser('https://example.com/late');
    expect(html).toContain('late');
  });

  it('schedules idle shutdown that closes the singleton after the timeout', async () => {
    vi.useFakeTimers();
    const { fetchUrlWithBrowser } = await loadFreshModule();
    const browser = makeFakeBrowser();
    launchMock.mockResolvedValue(browser);

    await fetchUrlWithBrowser('https://example.com/a');
    // Fast-forward past IDLE_SHUTDOWN_MS (60 s).
    await vi.advanceTimersByTimeAsync(60_001);
    // Allow the setTimeout callback's async chain to resolve.
    await Promise.resolve();
    await Promise.resolve();

    expect(browser.close).toHaveBeenCalledTimes(1);

    // A subsequent call should launch a new Browser (singleton was cleared).
    const browser2 = makeFakeBrowser();
    launchMock.mockResolvedValueOnce(browser2);
    vi.useRealTimers();
    await fetchUrlWithBrowser('https://example.com/b');
    expect(launchMock).toHaveBeenCalledTimes(2);
  });
});

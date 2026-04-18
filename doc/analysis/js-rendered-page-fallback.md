# Analysis: JS-Rendered Page Fallback for `kb_ingest`

## Problem

When `kb_ingest` is given a URL for a JavaScript-rendered SPA (e.g. `https://relationaltechproject.org/`), it returns:

```
Error: No extractable content from <url>
```

The root cause: `fetch.ts` uses Node.js built-in `fetch()`, which retrieves raw HTML. SPAs ship a near-empty HTML shell and populate the DOM via JavaScript at runtime. `linkedom` + Mozilla Readability then see no meaningful content.

SPA detection already exists in `extract.ts` as two private checks, but they only identify the failure mode — they do not attempt recovery:
- `looksLikeSpaHtml(html)` at `extract.ts:176` — early check on raw HTML for noscript + SPA root div; throws from `extractContent` at line 79.
- `looksLikeJsOnlyPage(html, content)` at `extract.ts:200` — post-extraction check on noscript-message-dominated content; throws from `extractContent` at line 136.

---

## What the Pipeline Looks Like Today

```
kb-ingest.ts
  └── content-pipeline.ts::fetchAndExtract()
        ├── safetyChecker.checkUrl()       [blocklist]
        ├── fetch.ts::fetchUrl()           [Node fetch, raw HTML]
        │     └── validateUrl()            [SSRF: scheme, blocklist, DNS→private IP]
        ├── extract.ts::extractContent()   [linkedom + Readability]
        │     ├── looksLikeSpaHtml()       [detects SPA early → throws]
        │     └── looksLikeJsOnlyPage()    [detects SPA late → throws]
        └── validateContent()              [quality checks]
```

Both SPA checks currently throw plain `Error`s from inside `extractContent`. To branch cleanly on them, `extractContent` should throw a typed `JsRenderRequiredError` for those two cases, which `content-pipeline.ts::fetchAndExtract()` can catch and use as the fallback trigger.

---

## Options

### Option A — Playwright headless browser (recommended)

Playwright launches a real Chromium/Firefox/WebKit instance, executes JavaScript, waits for the DOM to settle, then returns the rendered HTML.

**Integration point:** `content-pipeline.ts::fetchAndExtract()`, after detecting a JS-only page:

```
fetch raw HTML  →  SPA detected?
                      yes → launch Playwright, get rendered HTML → extract
                      no  → extract as today
```

**Pros:**
- Handles any SPA: React, Vue, Angular, Next.js, Nuxt, Gatsby, etc.
- Full JS execution — dynamic routes, lazy-loaded content, CSR hydration all work
- No external service dependency; runs entirely locally/server-side
- Consistent with existing SSRF protections (same URL validation applies before the Playwright call)

**Cons:**
- Slow: cold start 2–5 s, page render 3–15 s (vs. <1 s for plain fetch)
- Adds a system-level dependency (browser binaries) that complicates deployment
- Resource-intensive; headless browser processes can leak if not managed carefully

**Install footprint (accepted tradeoff):**
The `playwright` npm package is ~8 MB; its `postinstall` hook downloads a Chromium binary (~310–360 MB on macOS, ~280–320 MB on Linux). Total install cost is ~350 MB. ChaosKB accepts this cost up front in exchange for robustness: the fallback works on first use with no extra user setup, no `npx playwright install` step, no "this URL needs JS rendering, please install Chromium" error paths.

**Which Playwright package:**
The Playwright project ships four installation paths (Playwright Test, Playwright CLI, Playwright MCP, Playwright Library). ChaosKB needs the **Playwright Library** (`npm i playwright`) — programmatic browser automation from within our own Node code. The other paths are wrong fits:
- *Playwright Test* is a test-runner framework; ChaosKB isn't running tests.
- *Playwright CLI* is a global interactive CLI for coding agents; ChaosKB needs in-process API access.
- *Playwright MCP* exposes browser control to an LLM for agent-driven navigation. Stacking an MCP-in-an-MCP for deterministic "render this URL" rendering adds an LLM-in-the-loop we don't need.

**SSRF safety:** SSRF protections currently live in `fetch.ts::validateUrl()` and DNS resolution checks (lines 74–129). These must also gate the Playwright call — validate and DNS-check the URL before passing it to the browser. Do not rely on Playwright's own networking stack for security.

**Wait strategy:** Use `page.waitForLoadState('networkidle')` with a timeout (e.g. 15 s). This waits until there are no more than 2 in-flight network requests for 500 ms, which covers most SPA hydration patterns. Add a fallback to `domcontentloaded` if `networkidle` times out.

**Memory/process hygiene:** Always close the browser context in a `finally` block. Consider a module-level singleton browser instance with a keep-alive timeout to amortize startup cost across sequential ingestions.

---

### Option B — External rendering service

Services like [Jina Reader](https://jina.ai/reader/) (`https://r.jina.ai/<url>`) or [Browserless](https://browserless.io/) expose a REST API that renders a page and returns clean Markdown or HTML.

**Pros:**
- Zero local browser install; no binary dependency
- Fast to implement: swap `fetchUrl()` for a call to `https://r.jina.ai/<url>`
- Jina Reader returns clean Markdown directly, bypassing the Readability step

**Cons:**
- External network dependency — availability, latency, rate limits
- Privacy: every ingested URL is sent to a third party
- Jina Reader rewrites content and may strip structure useful for embeddings
- Inconsistent with the project's offline/local-first design (all data is encrypted locally; routing URLs through a third-party service contradicts this)
- SSRF protections must wrap the outbound call to prevent SSRF via the external service

**Verdict:** Not recommended given the local-first, privacy-focused architecture.

---

### Option C — Pre-render cache / Rendertron

Self-hosted [Rendertron](https://github.com/GoogleChrome/rendertron) or [Prerender.io](https://prerender.io/) sits in front of the fetch pipeline and pre-renders pages on demand.

**Pros:** Caching amortizes render cost for repeatedly-ingested domains

**Cons:** Requires running and maintaining a separate service. Overkill for a local tool. Same privacy concerns as Option B if hosted externally.

**Verdict:** Not worth the operational complexity.

---

## Recommended Solution: Option A (Playwright Library, regular dependency)

### Implementation sketch

**1. Add dependency**

```json
// src/package.json
"dependencies": {
  "playwright": "^1.x"
}
```

The `playwright` package's `postinstall` hook downloads Chromium automatically on `npm install`. No extra `npx playwright install` step is required in the normal install flow.

**2. Introduce `JsRenderRequiredError` in `extract.ts`**

Replace the two plain `Error` throws at `extract.ts:79` and `extract.ts:136` with a typed error so `content-pipeline.ts` can branch on SPA detection without string-matching messages:

```typescript
export class JsRenderRequiredError extends Error {
  constructor(public readonly url: string) {
    super(`This page requires JavaScript to render its content (${url}).`);
    this.name = 'JsRenderRequiredError';
  }
}
```

Both existing SPA-detection sites in `extractContent` throw `new JsRenderRequiredError(url)`.

**3. New module: `src/pipeline/fetch-browser.ts`**

A module-level singleton Chromium instance amortizes the 2–5 s cold start across sequential ingestions. The browser launches lazily on first use and self-closes after an idle timeout to release memory when ingestion is bursty but infrequent. Each request gets its own `BrowserContext` for cookie/cache isolation.

```typescript
import { chromium, type Browser } from 'playwright';
import { validateUrl, MAX_RESPONSE_BYTES } from './fetch.js';

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
    const browser = await p;
    await browser?.close();
  }, IDLE_SHUTDOWN_MS);
  idleTimer.unref(); // don't hold the event loop open at process exit
}

export async function fetchUrlWithBrowser(url: string): Promise<string> {
  // Single SSRF guard: validateUrl handles scheme, hostname blocklist,
  // IP-literal check, DNS lookup, and per-address private-IP rejection.
  await validateUrl(url);

  const browser = await getBrowser();
  const context = await browser.newContext(); // fresh cookies/storage per call
  try {
    const page = await context.newPage();
    await page.goto(url, { waitUntil: 'networkidle', timeout: NAV_TIMEOUT_MS })
      .catch(() =>
        page.goto(url, { waitUntil: 'domcontentloaded', timeout: NAV_TIMEOUT_MS })
      );
    const html = await page.content();
    if (html.length > MAX_RESPONSE_BYTES) {
      throw new Error(
        `Rendered page exceeds ${MAX_RESPONSE_BYTES / 1024 / 1024} MB limit.`
      );
    }
    return html;
  } finally {
    await context.close();
    scheduleIdleShutdown();
  }
}
```

Default Playwright UA is used (no spoofing). UA-blocked sites are out of scope; users can save to PDF and ingest that.

**Singleton shutdown wiring.** `idleTimer.unref()` ensures the timer doesn't keep the Node event loop alive. When the MCP stdio transport closes and the process exits naturally, Node will tear down the Chromium subprocess. No explicit `SIGINT`/`SIGTERM` handler is required, and one isn't added here — the MCP server currently has no such hook and introducing one for this alone is unwarranted.

**4. Modify `content-pipeline.ts::fetchAndExtract()`**

Hook in after the first `extractContent` throws `JsRenderRequiredError`:

```typescript
async fetchAndExtract(url: string): Promise<ExtractedContent> {
  if (!this.config._skipSafetyCheck) {
    const urlCheck = await safetyChecker.checkUrl(url);
    if (urlCheck.decision !== 'allow') {
      throw new Error(`URL blocked: ${urlCheck.reason ?? urlCheck.decision}`);
    }
  }

  const result = await fetchUrl(url, this.config);

  let html = result.html;
  let extracted: ExtractedContent;
  try {
    extracted = extractContent(html, result.finalUrl);
  } catch (err) {
    if (err instanceof JsRenderRequiredError) {
      html = await fetchUrlWithBrowser(result.finalUrl);
      extracted = extractContent(html, result.finalUrl); // may still throw if render failed
    } else {
      throw err;
    }
  }

  const issues = validateContent(html, extracted);
  // ... existing error/warning split unchanged
  return extracted;
}
```

Notes:
- `validateContent` runs on the **rendered** HTML when the fallback fires (correct — that's what actually produced the text).
- If `extractContent` throws `JsRenderRequiredError` a second time (site still looks SPA-like after render), we surface that error as-is. That's the right UX for an unrenderable page.

**5. Error surfacing**

Because Playwright is a regular dependency and Chromium installs at `npm install` time, runtime "browser not available" errors should not occur under normal conditions. If the browser launch does fail (corrupted install, sandbox restrictions, missing system libraries on exotic Linux distros), surface the underlying Playwright error unchanged — it's specific enough to diagnose. Recovery is `npx playwright install chromium`.

---

## Security Considerations

| Risk | Mitigation |
|------|-----------|
| SSRF via browser | Re-run `validateUrl()` + DNS checks before Playwright call (same as plain fetch) |
| Prompt injection via rendered DOM | Existing `stripHiddenElements()` in `extract.ts` still runs on rendered HTML |
| Cross-request state leakage via singleton | Fresh `BrowserContext` per call; close context in `finally` |
| Resource exhaustion | Singleton self-closes after `IDLE_SHUTDOWN_MS`; per-call `context.close()`; per-navigation 15 s timeout |
| Malicious JS execution | Headless browser is sandboxed by OS; no elevated privileges needed |
| Large rendered pages | Enforce existing 10 MB limit on `page.content()` result length |

---

## Design Decisions

1. **Singleton browser process.** A module-level Chromium instance is launched lazily on first use and reused across calls, then closed after 60 s of idle. This amortizes the 2–5 s cold start over sequential ingestions while still releasing ~200 MB of resident memory when the fallback isn't active. Each call gets a fresh `BrowserContext` so cookies/cache can't leak between ingestions.

2. **Default Playwright UA.** No UA spoofing. Some sites block headless browsers by UA string, but spoofing starts an arms race with anti-bot systems and is out of scope.

3. **Fallback is not opt-in.** Playwright is a regular dependency, so the fallback is always available and triggers automatically whenever `looksLikeJsOnlyPage()` returns true. No config flag, no install prompt, no user-visible "this URL needs JS" state.

4. **No cookie/session support.** Pages requiring login are out of scope for this fallback. Users can save the page as PDF and ingest that instead.

---

## Test Plan

**Unit — `extract.ts`**
- `extractContent` on a noscript-dominated SPA shell throws `JsRenderRequiredError` (from the `looksLikeSpaHtml` path).
- `extractContent` on a page where only the noscript fallback survives Readability throws `JsRenderRequiredError` (from the `looksLikeJsOnlyPage` path).
- `extractContent` on a normal article page returns `ExtractedContent` with no error.

**Unit — `fetch-browser.ts`**
- Singleton lifecycle: two sequential `fetchUrlWithBrowser()` calls reuse the same `Browser` instance (spy on `chromium.launch`, assert one invocation).
- Idle shutdown: after `IDLE_SHUTDOWN_MS`, `browserPromise` is nulled and the underlying browser is closed (fake timers).
- SSRF: `fetchUrlWithBrowser('http://169.254.169.254/')` rejects via `validateUrl` **before** any browser launch (spy on `chromium.launch`, assert zero invocations).
- Size cap: rendered content exceeding `MAX_RESPONSE_BYTES` throws; the context is still closed (assert `context.close` called).
- Context isolation: two calls use different `BrowserContext` instances (spy on `browser.newContext`).

**Integration — `content-pipeline.ts`**
- End-to-end on a fixture SPA (served from a local static server with `<div id="root"></div>` and a small JS bundle): `fetchAndExtract()` returns non-empty `ExtractedContent`. Skipped in CI if Chromium isn't runnable; gated behind an env flag.
- Non-SPA page: `fetchAndExtract()` does **not** invoke `fetchUrlWithBrowser` (spy on the export).
- `JsRenderRequiredError` thrown a second time (render produced another SPA shell) propagates out of `fetchAndExtract`.

**Manual smoke**
- Ingest `https://relationaltechproject.org/` (the original failing URL) and verify content extraction succeeds.

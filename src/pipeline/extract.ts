/**
 * Content extraction from HTML using Mozilla Readability.
 *
 * Parses HTML with `linkedom` and runs it through Readability to pull out
 * the main article content, stripped of navigation, ads, and boilerplate.
 */

import { basename } from 'node:path';
import { Readability } from '@mozilla/readability';
import { parseHTML } from 'linkedom';
import type { ExtractedContent } from './types.js';

/**
 * Thrown when a page appears to require client-side JavaScript to render
 * its content. Callers can catch this to invoke a headless-browser fallback.
 */
export class JsRenderRequiredError extends Error {
  constructor(public readonly url: string) {
    super(
      `This page appears to require JavaScript to render its content (${url}). ` +
      `Only the noscript fallback was captured.`,
    );
    this.name = 'JsRenderRequiredError';
  }
}

/**
 * Regex matching inline `style` attribute values that visually hide an element.
 *
 * These patterns detect CSS-based hiding tricks that attackers use to embed
 * invisible prompt-injection payloads in web pages.  Because `linkedom` does
 * not compute styles, Readability would otherwise include this hidden text.
 */
const HIDDEN_STYLE_RE =
  /display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|em|rem|%)?\s*(?:;|$)|opacity\s*:\s*0(?:\.\d+)?(?:;|$)|position\s*:\s*(?:absolute|fixed)[\s\S]*?(?:left|top)\s*:\s*-\d{4,}|clip\s*:\s*rect\(\s*0/i;

/**
 * Strip elements that are visually hidden from the DOM before Readability runs.
 *
 * Removes:
 * - Elements with the `hidden` attribute
 * - Elements with `aria-hidden="true"`
 * - `<noscript>` elements (content is irrelevant for non-JS fetching)
 * - Elements whose inline `style` matches common hiding patterns
 */
function stripHiddenElements(document: any): void {
  // Remove <noscript> — irrelevant when we don't execute JS
  for (const el of document.querySelectorAll('noscript')) {
    el.remove();
  }

  // Remove elements with the `hidden` attribute
  for (const el of document.querySelectorAll('[hidden]')) {
    el.remove();
  }

  // Remove elements with aria-hidden="true"
  for (const el of document.querySelectorAll('[aria-hidden="true"]')) {
    el.remove();
  }

  // Remove elements whose inline style indicates visual hiding
  for (const el of document.querySelectorAll('[style]')) {
    const style = el.getAttribute('style') ?? '';
    if (HIDDEN_STYLE_RE.test(style)) {
      el.remove();
    }
  }
}

/** Sanitize a source identifier for error messages (strip full paths). */
function safeSourceLabel(url: string): string {
  if (url.startsWith('/') || /^[A-Z]:\\/i.test(url)) return basename(url);
  return url;
}

/**
 * Extract the main article content from an HTML string.
 *
 * @param html - The raw HTML string to extract content from.
 * @param url - The source URL (used for resolving relative links and metadata).
 * @returns Extracted content with title, plain text, URL, and byte length.
 * @throws If no article content can be extracted.
 */
export function extractContent(html: string, url: string): ExtractedContent {
  if (!html || html.trim().length === 0) {
    throw new Error(`Empty HTML content from ${safeSourceLabel(url)}`);
  }

  // Early SPA detection: check the raw HTML before we strip <noscript>.
  // SPA pages have <noscript> as their only meaningful content; once we strip it
  // below, there's nothing left to extract and we'd get a confusing error.
  if (looksLikeSpaHtml(html)) {
    throw new JsRenderRequiredError(safeSourceLabel(url));
  }

  const { document } = parseHTML(html);

  // Strip visually-hidden elements before Readability sees them.
  // This prevents CSS-based prompt-injection payloads from surviving extraction.
  stripHiddenElements(document);

  // Attempt Readability extraction
  const reader = new Readability(document as any);
  const article = reader.parse();

  let title: string;
  let rawContent: string;

  if (article && article.textContent && article.textContent.trim().length > 0) {
    title = article.title || '';
    rawContent = article.textContent;
  } else {
    // Fallback: extract text from body (strip script/style/hidden first)
    // Wrap in a full HTML document to ensure linkedom creates a body element
    const wrappedHtml = html.includes('<body') ? html : `<html><body>${html}</body></html>`;
    const { document: fallbackDoc } = parseHTML(wrappedHtml);
    stripHiddenElements(fallbackDoc);
    for (const el of fallbackDoc.querySelectorAll('script, style')) {
      el.remove();
    }
    const body = fallbackDoc.querySelector('body');
    rawContent = body ? body.textContent ?? '' : '';

    if (rawContent.trim().length === 0) {
      throw new Error(`No extractable content from ${safeSourceLabel(url)}`);
    }

    title = '';
  }

  // Fallback title: try <title> tag from a fresh parse
  if (!title) {
    const { document: titleDoc } = parseHTML(html);
    const titleEl = titleDoc.querySelector('title');
    title = titleEl?.textContent?.trim() ?? '';
  }

  // Clean up the text: collapse whitespace runs, trim lines
  const content = cleanText(rawContent);

  if (content.length === 0) {
    throw new Error(`No extractable content from ${url}`);
  }

  // Detect JavaScript-only SPA pages that didn't render
  if (looksLikeJsOnlyPage(html, content)) {
    throw new JsRenderRequiredError(safeSourceLabel(url));
  }

  const byteLength = Buffer.byteLength(content, 'utf-8');

  return { title, content, url, byteLength };
}

/** Patterns that indicate a noscript fallback message. */
const NOSCRIPT_PATTERNS = [
  /you need to enable javascript/i,
  /please enable javascript/i,
  /javascript is required/i,
  /javascript is disabled/i,
  /this app requires javascript/i,
  /enable javascript to run this app/i,
  /this application requires javascript/i,
  /javascript must be enabled/i,
  /works best with javascript enabled/i,
  /this site requires javascript/i,
];

/**
 * Minimum content length (in characters) below which a noscript message
 * is treated as the *entire* page content rather than an incidental mention.
 * A real article that happens to discuss JavaScript would be much longer.
 */
const SPA_CONTENT_THRESHOLD = 500;

/**
 * Quick pre-extraction check on raw HTML for SPA shells.
 *
 * Detects pages that have a noscript message AND an empty SPA root container,
 * which is a strong signal that the page requires JS.  This runs before
 * `<noscript>` stripping so we can give a clear error message.
 */
function looksLikeSpaHtml(html: string): boolean {
  const hasNoscript = /<noscript\b[^>]*>[^<]*<\/noscript>/i.test(html);
  if (!hasNoscript) return false;

  const hasNoscriptMessage = NOSCRIPT_PATTERNS.some((p) => p.test(html));
  if (!hasNoscriptMessage) return false;

  const hasSpaRoot =
    /<div\s+id=["'](?:root|app|__next|__nuxt|__gatsby)["']\s*>\s*<\/div>/i.test(html);

  return hasSpaRoot;
}

/**
 * Detect if extracted content is likely a JavaScript-only noscript fallback.
 *
 * The heuristic is intentionally conservative: both a short extracted text
 * AND a noscript-style message must be present.  A real article that
 * discusses JavaScript would have far more than 500 characters of content.
 *
 * Because `<noscript>` elements are stripped during hidden-element removal
 * (they are irrelevant for non-JS fetching), we check the raw HTML for
 * noscript patterns rather than the extracted text.
 */
function looksLikeJsOnlyPage(html: string, extractedText: string): boolean {
  // Check raw HTML for noscript messages (since <noscript> is stripped before extraction)
  const hasNoscriptMessage =
    NOSCRIPT_PATTERNS.some((p) => p.test(extractedText)) ||
    NOSCRIPT_PATTERNS.some((p) => p.test(html));
  if (!hasNoscriptMessage) return false;

  // Short content + noscript message → almost certainly an SPA shell
  if (extractedText.length < SPA_CONTENT_THRESHOLD) return true;

  // Longer content but the HTML has an empty SPA root container
  // (e.g. <div id="root"></div>) alongside the noscript message
  const hasSpaRoot =
    /<div\s+id=["'](?:root|app|__next|__nuxt|__gatsby)["']\s*>\s*<\/div>/i.test(html);

  return hasSpaRoot;
}

/**
 * Clean extracted text by stripping steganographic characters,
 * collapsing whitespace, and trimming.
 */
function cleanText(text: string): string {
  return text
    .replace(/[\u2028\u2029]/g, '\n')                                // Unicode line/paragraph separators → newline
    .replace(/[\u200B-\u200F\u202A-\u202F\u2060-\u206F\uFEFF]/g, '') // strip zero-width / bidi / invisible chars
    .replace(/[\t ]+/g, ' ')       // collapse horizontal whitespace
    .replace(/\n{3,}/g, '\n\n')    // collapse excessive newlines
    .replace(/^ +| +$/gm, '')      // trim each line
    .trim();
}

/**
 * Content validation for the ingestion pipeline.
 *
 * Runs quality checks on fetched HTML and extracted content, returning
 * structured issues.  Errors block ingestion; warnings are surfaced
 * to the user alongside the stored content.
 *
 * Checks are organised into three tiers:
 *   1. Pattern matching  — known services / phrases
 *   2. Structural HTML   — HTML characteristics regardless of service
 *   3. Content heuristics — statistical properties of extracted text
 *
 * All patterns are English-only for now.
 */

import type { ExtractedContent } from './types.js';
import { getSafetyChecker, getInjectionPolicy, getSecretsPolicy } from './safety.js';

// ===== Public types ========================================================

export interface ContentIssue {
  severity: 'error' | 'warning';
  code: string;
  message: string;
}

// ===== Thresholds ==========================================================

const THIN_CONTENT_LIMIT = 50;
const SHORT_CONTENT_LIMIT = 200;
const PAYWALL_CONTENT_LIMIT = 500;
const SOFT_404_CONTENT_LIMIT = 1000;
const ERROR_PAGE_CONTENT_LIMIT = 500;
const MAINTENANCE_CONTENT_LIMIT = 500;
const REDIRECT_CONTENT_LIMIT = 300;
const LOGIN_FORM_CONTENT_LIMIT = 500;
const COOKIE_CONSENT_TEXT_LIMIT = 300;
const COOKIE_CONSENT_HTML_LIMIT = 200;
const ACCESS_RESTRICTED_CONTENT_LIMIT = 500;
const NAV_ONLY_CONTENT_LIMIT = 500;

// Content-to-HTML ratio
const MIN_HTML_SIZE_FOR_RATIO = 2000;
const RATIO_ERROR_THRESHOLD = 0.01;
const RATIO_ERROR_HTML_MIN = 5000;
const RATIO_WARNING_THRESHOLD = 0.03;
const RATIO_WARNING_HTML_MIN = 3000;

// Repetitive content
const MIN_SENTENCES_FOR_REPETITION = 4;
const REPETITION_UNIQUE_RATIO = 0.4;
const MAX_SENTENCE_REPEATS = 3;

// Encoding garbage
const REPLACEMENT_CHAR_RATIO = 0.05;
const MOJIBAKE_COUNT_THRESHOLD = 5;
const MOJIBAKE_TEXT_LIMIT = 2000;
const CONTROL_CHAR_RATIO = 0.02;

// Zero-width character steganography
const ZERO_WIDTH_WARN_THRESHOLD = 10;

/** Cap HTML scanned by pattern-matching to avoid perf issues on huge pages. */
const HTML_SCAN_LIMIT = 200_000;

// ===== Pattern sets ========================================================

// --- Bot / WAF / DDoS ------------------------------------------------------

const BOT_BLOCK_HTML_PATTERNS = [
  // Cloudflare
  /challenges\.cloudflare\.com/i,
  /cf[-_]chl[-_]opt/i,
  /cf-browser-verification/i,
  /id=["']challenge-running["']/i,
  // Akamai
  /ak_bmsc/i,
  /_sec\/cp_challenge/i,
  // AWS WAF
  /awswaf/i,
  // Imperva / Incapsula
  /incap_ses/i,
  /visid_incap/i,
  // PerimeterX / HUMAN
  /perimeterx/i,
  /px-captcha/i,
  // DataDome
  /datadome/i,
  // Kasada
  /cd\.kasada\.io/i,
  // DDoS protection
  /ddos protection by/i,
  /sucuri website firewall/i,
  /protection by incapsula/i,
];

const BOT_BLOCK_TEXT_PATTERNS = [
  // Cloudflare
  /checking if the site connection is secure/i,
  /attention required.{0,10}cloudflare/i,
  // Generic WAF
  /^access denied$/im,
  /you have been blocked/i,
  /request blocked/i,
  /this request was blocked by the security rules/i,
  /your (?:ip|access) (?:has been|is) (?:blocked|banned|restricted)/i,
  /automated (?:access|requests?) (?:detected|blocked)/i,
  /unusual traffic from your (?:computer|network)/i,
];

// --- CAPTCHA ---------------------------------------------------------------

const CAPTCHA_HTML_PATTERNS = [
  /g-recaptcha/i,
  /h-captcha/i,
  /class=["'][^"']*hcaptcha/i,
  /captcha-delivery\.com/i,
  // Cloudflare Turnstile
  /challenges\.cloudflare\.com\/turnstile/i,
  /cf-turnstile/i,
  // Arkose Labs / FunCaptcha
  /funcaptcha/i,
  /arkoselabs\.com/i,
  // GeeTest
  /geetest/i,
  // Generic
  /id=["']captcha/i,
  /class=["'][^"']*captcha/i,
];

const CAPTCHA_TEXT_PATTERNS = [
  /verify you are (?:a )?human/i,
  /complete the security check/i,
  /i[''\u2019]m not a robot/i,
  /prove you[''\u2019]re not a robot/i,
  /please (?:complete|solve) (?:the|this) (?:captcha|challenge|puzzle)/i,
];

// --- Soft 404 --------------------------------------------------------------

const SOFT_404_TITLE_RE =
  /<title[^>]*>[^<]*(?:404|not\s*found|page\s*(?:not|doesn[''\u2019]t)\s*(?:exist|found))[^<]*<\/title>/i;

const SOFT_404_TEXT_PATTERNS = [
  /^(?:404|page not found|not found)\s*$/im,
  /this page (?:doesn[''\u2019]t|does not|could not) (?:exist|be found)/i,
  /the page you (?:are|were) looking for.*(?:not found|doesn[''\u2019]t exist|no longer exists|has been (?:removed|moved|deleted))/i,
  /we couldn[''\u2019]t find (?:that|this|the) page/i,
  /nothing (?:was )?found here/i,
  /oops.*(?:page|content).*(?:not found|gone|missing)/i,
  /(?:sorry|unfortunately).*(?:page|url).*(?:not found|doesn[''\u2019]t exist|no longer available)/i,
];

const SOFT_404_META_RE =
  /<meta[^>]+(?:prerender-status-code|http-equiv=["']status["'])[^>]+(?:content=["']404["']|404)/i;

// --- Error page ------------------------------------------------------------

const ERROR_PAGE_TITLE_RE =
  /<title[^>]*>[^<]*(?:500|error|something went wrong|internal server error|service unavailable|bad gateway)[^<]*<\/title>/i;

const ERROR_PAGE_TEXT_PATTERNS = [
  /^(?:something went wrong|an error (?:occurred|has occurred)|internal server error|server error|service unavailable|bad gateway|gateway timeout)\s*$/im,
  /we[''\u2019]re having (?:trouble|problems|issues|technical difficulties)/i,
  /unexpected error/i,
  /application error/i,
];

const ERROR_PAGE_TEXT_GATED = [
  /please try again later/i,
];

const ERROR_PAGE_HTML_PATTERNS = [
  /id=["']error-page["']/i,
  /class=["'][^"']*(?:error-page|error-container|error-boundary)/i,
  /next-error/i,
];

// --- Maintenance / coming-soon ---------------------------------------------

const MAINTENANCE_TEXT_PATTERNS = [
  /(?:site|website|page) (?:is )?(?:under|undergoing) (?:maintenance|construction)/i,
  /we[''\u2019](?:re|ll be) (?:back|right back|up) (?:shortly|soon)/i,
  /(?:currently|temporarily) (?:unavailable|down for maintenance)/i,
  /under construction/i,
  /scheduled maintenance/i,
  /we are (?:updating|upgrading|performing maintenance)/i,
];

const MAINTENANCE_TEXT_GATED = [
  /coming soon/i,
];

// --- Cookie consent --------------------------------------------------------

const COOKIE_TEXT_PATTERNS = [
  /we use cookies/i,
  /this (?:website|site) uses cookies/i,
  /cookie (?:policy|preferences|settings|consent)/i,
  /by continuing.*you (?:agree|consent)/i,
  /manage (?:your )?(?:cookie|privacy) (?:preferences|settings)/i,
  /accept (?:all|cookies)/i,
];

const COOKIE_HTML_PATTERNS = [
  /class=["'][^"']*(?:cookie-consent|cookie-banner|cookie-wall|consent-wall|gdpr-banner)/i,
  /id=["'](?:cookie-consent|cookie-banner|consent)/i,
];

// --- Paywall / login wall --------------------------------------------------

const PAYWALL_PATTERNS = [
  /subscribe to (?:continue|read|access)/i,
  /sign (?:in|up) to (?:continue|read|access|view)/i,
  /log in to (?:continue|read|access|view)/i,
  /create an? (?:free )?account/i,
  /members only/i,
  /premium content/i,
  /start your (?:free )?trial/i,
  /(?:this|the) (?:article|story|content|post) is (?:for|available to|exclusive to) (?:subscribers|members|premium)/i,
  /(?:free )?articles? remaining/i,
  /you(?:[''\u2019]ve| have) (?:reached|used|read) your (?:(?:free|monthly|weekly) )?(?:article|story)? ?limit/i,
  /register (?:for free )?to (?:continue|read|access)/i,
  /unlock (?:this|the|full) (?:article|story|content)/i,
  /already a (?:subscriber|member)/i,
];

// --- Redirect interstitial -------------------------------------------------

const REDIRECT_TEXT_PATTERNS = [
  /you are (?:now )?being (?:redirected|transferred|forwarded)/i,
  /(?:click here|tap here) if you are not (?:automatically )?redirected/i,
  /if you are not redirected.*click/i,
  /redirecting (?:you )?(?:to|in \d+ seconds)/i,
];

const REDIRECT_META_REFRESH_RE = /<meta\s+http-equiv=["']refresh["'][^>]*url=/i;

// --- Age gate / geo-block --------------------------------------------------

const ACCESS_RESTRICTED_TEXT_PATTERNS = [
  /(?:verify|confirm) (?:your|that you are).*(?:age|over \d+|at least \d+)/i,
  /you must be (?:\d+|of legal age)/i,
  /this content is (?:not available|unavailable|restricted) in your (?:country|region|area|location)/i,
  /(?:geo|geographic(?:ally)?|region(?:ally)?)[\s-](?:blocked|restricted|unavailable)/i,
  /content not available in your (?:country|region)/i,
];

const ACCESS_RESTRICTED_HTML_PATTERNS = [
  /class=["'][^"']*(?:age-gate|age-verification|age-check)/i,
  /id=["']age-gate/i,
];

// --- Login form (HTML structure) -------------------------------------------

const LOGIN_TEXT_PATTERNS = [
  /sign in/i,
  /log in/i,
  /forgot (?:your )?password/i,
  /remember me/i,
  /don[''\u2019]t have an account/i,
];

// --- Meta robots -----------------------------------------------------------

const NOINDEX_RE =
  /<meta[^>]+(?:name=["']robots["'][^>]+content=["'][^"']*noindex|content=["'][^"']*noindex[^"']*["'][^>]+name=["']robots["'])/i;

// --- Encoding garbage ------------------------------------------------------

const MOJIBAKE_RE = /\u00C3[\u00A9\u00A8\u00BC]|\u00E2\u0080[\u0099\u009C\u009D]|\u00C2[\u00A0-\u00BF]/g;
const CONTROL_CHAR_RE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;

// --- Zero-width character steganography ------------------------------------

const ZERO_WIDTH_RE = /[\u200B-\u200F\u202A-\u202F\u2060-\u206F\uFEFF]/g;


// ===== Public API ==========================================================

/**
 * Validate fetched HTML and its extracted content.
 *
 * Returns all detected issues (not just the first).  Callers should
 * treat `error`-severity issues as ingestion blockers and `warning`
 * issues as informational.
 */
export function validateContent(
  html: string,
  extracted: ExtractedContent,
): ContentIssue[] {
  const issues: ContentIssue[] = [];
  const text = extracted.content;
  // Cap HTML to avoid perf issues on very large pages
  const scanHtml = html.length > HTML_SCAN_LIMIT ? html.slice(0, HTML_SCAN_LIMIT) : html;

  // --- Tier 1: Pattern matching (known blockers) ---------------------------
  checkBotBlocked(scanHtml, text, issues);
  checkCaptcha(scanHtml, text, issues);
  checkSoft404(scanHtml, text, issues);
  checkErrorPage(scanHtml, text, issues);
  checkMaintenancePage(text, issues);
  checkCookieConsentPage(scanHtml, text, issues);

  // --- Tier 2: Structural HTML analysis ------------------------------------
  checkContentToHtmlRatio(html, text, issues);
  checkLoginFormPage(scanHtml, text, issues);
  checkMetaRobotsNoindex(scanHtml, issues);

  // --- Tier 3: Content heuristics ------------------------------------------
  checkThinContent(text, issues);
  checkShortContent(text, issues);
  checkPaywall(text, issues);
  checkRedirectInterstitial(scanHtml, text, issues);
  checkAccessRestricted(scanHtml, text, issues);
  checkRepetitiveContent(text, issues);
  checkNavigationOnly(text, issues);
  checkEncodingGarbage(text, issues);
  checkZeroWidthCharacters(text, issues);
  checkInjectionAndSecrets(text, issues);

  return issues;
}

/**
 * Validate extracted content from a local file.
 *
 * Runs only Tier 3 (content heuristic) checks.  Tier 1 (pattern matching)
 * and Tier 2 (structural HTML analysis) are specific to URL-fetched content.
 */
export function validateFileContent(extracted: ExtractedContent): ContentIssue[] {
  const issues: ContentIssue[] = [];
  const text = extracted.content;

  checkThinContent(text, issues);
  checkShortContent(text, issues);
  checkRepetitiveContent(text, issues);
  checkNavigationOnly(text, issues);
  checkEncodingGarbage(text, issues);
  checkZeroWidthCharacters(text, issues);
  checkInjectionAndSecrets(text, issues);

  return issues;
}

// ===== Tier 1: Pattern matching ============================================

function checkBotBlocked(html: string, text: string, issues: ContentIssue[]): void {
  if (BOT_BLOCK_HTML_PATTERNS.some((p) => p.test(html))) {
    issues.push({
      severity: 'error',
      code: 'bot-blocked',
      message:
        'This page returned an anti-bot challenge instead of content. ' +
        'The site blocks automated requests.',
    });
    return;
  }
  if (BOT_BLOCK_TEXT_PATTERNS.some((p) => p.test(text))) {
    issues.push({
      severity: 'error',
      code: 'bot-blocked',
      message:
        'This page returned an "Access Denied" or bot-detection response. ' +
        'The site blocks automated requests.',
    });
  }
}

function checkCaptcha(html: string, text: string, issues: ContentIssue[]): void {
  if (CAPTCHA_HTML_PATTERNS.some((p) => p.test(html)) || CAPTCHA_TEXT_PATTERNS.some((p) => p.test(text))) {
    issues.push({
      severity: 'error',
      code: 'captcha',
      message:
        'This page contains a CAPTCHA challenge. ' +
        'The site requires human verification before serving content.',
    });
  }
}

function checkSoft404(html: string, text: string, issues: ContentIssue[]): void {
  if (SOFT_404_TITLE_RE.test(html) || SOFT_404_META_RE.test(html)) {
    issues.push({
      severity: 'error',
      code: 'soft-404',
      message: 'This page appears to be a "not found" page that returned HTTP 200.',
    });
    return;
  }
  if (text.length < SOFT_404_CONTENT_LIMIT && SOFT_404_TEXT_PATTERNS.some((p) => p.test(text))) {
    issues.push({
      severity: 'error',
      code: 'soft-404',
      message: 'This page appears to be a "not found" page that returned HTTP 200.',
    });
  }
}

function checkErrorPage(html: string, text: string, issues: ContentIssue[]): void {
  if (ERROR_PAGE_TITLE_RE.test(html) || ERROR_PAGE_HTML_PATTERNS.some((p) => p.test(html))) {
    issues.push({
      severity: 'error',
      code: 'error-page',
      message: 'This page appears to be an error or status page, not article content.',
    });
    return;
  }
  if (ERROR_PAGE_TEXT_PATTERNS.some((p) => p.test(text))) {
    issues.push({
      severity: 'error',
      code: 'error-page',
      message: 'This page appears to be an error or status page, not article content.',
    });
    return;
  }
  if (text.length < ERROR_PAGE_CONTENT_LIMIT && ERROR_PAGE_TEXT_GATED.some((p) => p.test(text))) {
    issues.push({
      severity: 'error',
      code: 'error-page',
      message: 'This page appears to be an error or status page, not article content.',
    });
  }
}

function checkMaintenancePage(text: string, issues: ContentIssue[]): void {
  if (MAINTENANCE_TEXT_PATTERNS.some((p) => p.test(text))) {
    issues.push({
      severity: 'error',
      code: 'maintenance-page',
      message: 'This page appears to be a maintenance or "under construction" notice.',
    });
    return;
  }
  if (text.length < MAINTENANCE_CONTENT_LIMIT && MAINTENANCE_TEXT_GATED.some((p) => p.test(text))) {
    issues.push({
      severity: 'error',
      code: 'maintenance-page',
      message: 'This page appears to be a maintenance or "coming soon" notice.',
    });
  }
}

function checkCookieConsentPage(html: string, text: string, issues: ContentIssue[]): void {
  if (text.length < COOKIE_CONSENT_HTML_LIMIT && COOKIE_HTML_PATTERNS.some((p) => p.test(html))) {
    issues.push({
      severity: 'error',
      code: 'cookie-consent-only',
      message:
        'The extracted content appears to be only a cookie-consent overlay. ' +
        'The actual page content was not captured.',
    });
    return;
  }
  if (text.length < COOKIE_CONSENT_TEXT_LIMIT && COOKIE_TEXT_PATTERNS.some((p) => p.test(text))) {
    issues.push({
      severity: 'error',
      code: 'cookie-consent-only',
      message:
        'The extracted content appears to be only a cookie-consent overlay. ' +
        'The actual page content was not captured.',
    });
  }
}

// ===== Tier 2: Structural HTML analysis ====================================

function checkContentToHtmlRatio(html: string, text: string, issues: ContentIssue[]): void {
  const htmlLen = html.length;
  if (htmlLen < MIN_HTML_SIZE_FOR_RATIO) return;

  const ratio = text.length / htmlLen;

  if (ratio < RATIO_ERROR_THRESHOLD && htmlLen > RATIO_ERROR_HTML_MIN) {
    issues.push({
      severity: 'error',
      code: 'low-content-ratio',
      message:
        `Only ${(ratio * 100).toFixed(1)}% of the page HTML is visible text ` +
        `(${text.length} chars from ${htmlLen} bytes of HTML). ` +
        'The page is almost entirely scripts/markup with negligible readable content.',
    });
    return;
  }

  if (ratio < RATIO_WARNING_THRESHOLD && htmlLen > RATIO_WARNING_HTML_MIN) {
    issues.push({
      severity: 'warning',
      code: 'low-content-ratio',
      message:
        `Only ${(ratio * 100).toFixed(1)}% of the page HTML is visible text. ` +
        'The content may be incomplete or partially rendered.',
    });
  }
}

function checkLoginFormPage(html: string, text: string, issues: ContentIssue[]): void {
  if (text.length >= LOGIN_FORM_CONTENT_LIMIT) return;
  // Fast path: no password field → not a login page
  if (!/<input[^>]+type=["']password["']/i.test(html)) return;
  if (LOGIN_TEXT_PATTERNS.some((p) => p.test(text))) {
    issues.push({
      severity: 'warning',
      code: 'login-form',
      message:
        'This page appears to be a login form rather than article content.',
    });
  }
}

function checkMetaRobotsNoindex(html: string, issues: ContentIssue[]): void {
  if (NOINDEX_RE.test(html)) {
    issues.push({
      severity: 'warning',
      code: 'noindex-page',
      message:
        'This page has a "noindex" robots directive — the publisher does not intend it to be indexed.',
    });
  }
}

// ===== Tier 3: Content heuristics ==========================================

function checkThinContent(text: string, issues: ContentIssue[]): void {
  if (text.length < THIN_CONTENT_LIMIT) {
    issues.push({
      severity: 'error',
      code: 'thin-content',
      message:
        `Extracted content is only ${text.length} characters — too short to be a real article. ` +
        'The page may be an error page, redirect landing, or access-restricted.',
    });
  }
}

function checkShortContent(text: string, issues: ContentIssue[]): void {
  if (text.length >= THIN_CONTENT_LIMIT && text.length < SHORT_CONTENT_LIMIT) {
    issues.push({
      severity: 'warning',
      code: 'short-content',
      message:
        `Extracted content is only ${text.length} characters. ` +
        'The page may be truncated, paywalled, or only partially rendered.',
    });
  }
}

function checkPaywall(text: string, issues: ContentIssue[]): void {
  if (text.length >= PAYWALL_CONTENT_LIMIT) return;
  if (PAYWALL_PATTERNS.some((p) => p.test(text))) {
    issues.push({
      severity: 'warning',
      code: 'possible-paywall',
      message:
        'The extracted content is short and contains language suggesting a paywall or login wall. ' +
        'The stored content may be incomplete.',
    });
  }
}

function checkRedirectInterstitial(html: string, text: string, issues: ContentIssue[]): void {
  if (text.length >= REDIRECT_CONTENT_LIMIT) return;
  const hasMetaRefresh = REDIRECT_META_REFRESH_RE.test(html);
  const hasRedirectText = REDIRECT_TEXT_PATTERNS.some((p) => p.test(text));
  if (hasMetaRefresh || hasRedirectText) {
    issues.push({
      severity: 'warning',
      code: 'redirect-interstitial',
      message:
        'This page appears to be a redirect interstitial. ' +
        'The actual destination content was not captured.',
    });
  }
}

function checkAccessRestricted(html: string, text: string, issues: ContentIssue[]): void {
  if (ACCESS_RESTRICTED_HTML_PATTERNS.some((p) => p.test(html))) {
    issues.push({
      severity: 'warning',
      code: 'access-restricted',
      message: 'This page appears to have an age-verification or region-restriction gate.',
    });
    return;
  }
  if (text.length < ACCESS_RESTRICTED_CONTENT_LIMIT && ACCESS_RESTRICTED_TEXT_PATTERNS.some((p) => p.test(text))) {
    issues.push({
      severity: 'warning',
      code: 'access-restricted',
      message: 'This page appears to have an age-verification or region-restriction gate.',
    });
  }
}

function checkRepetitiveContent(text: string, issues: ContentIssue[]): void {
  const sentences = text
    .split(/[.!?]+\s+/)
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s.length > 0);

  if (sentences.length < MIN_SENTENCES_FOR_REPETITION) return;

  const counts = new Map<string, number>();
  for (const s of sentences) {
    counts.set(s, (counts.get(s) ?? 0) + 1);
  }

  const uniqueRatio = counts.size / sentences.length;
  const maxRepeats = Math.max(...counts.values());

  if (uniqueRatio < REPETITION_UNIQUE_RATIO || maxRepeats > MAX_SENTENCE_REPEATS) {
    issues.push({
      severity: 'warning',
      code: 'repetitive-content',
      message:
        'The extracted content appears highly repetitive, which may indicate ' +
        'a broken extraction, placeholder page, or auto-generated content.',
    });
  }
}

function checkNavigationOnly(text: string, issues: ContentIssue[]): void {
  if (text.length >= NAV_ONLY_CONTENT_LIMIT) return;

  const lines = text.split('\n').filter((l) => l.trim().length > 0);
  if (lines.length < 3) return;

  // Lines that look like nav items: short, no sentence-ending punctuation
  const navLikeCount = lines.filter(
    (l) => l.trim().length < 30 && !/[.!?]$/.test(l.trim()),
  ).length;

  if (navLikeCount / lines.length > 0.7) {
    issues.push({
      severity: 'warning',
      code: 'navigation-only',
      message:
        'The extracted content appears to be mostly navigation links or menu items, ' +
        'not article text.',
    });
  }
}

function checkEncodingGarbage(text: string, issues: ContentIssue[]): void {
  // Replacement character ratio
  const replacementCount = (text.match(/\uFFFD/g) ?? []).length;
  if (text.length > 0 && replacementCount / text.length > REPLACEMENT_CHAR_RATIO) {
    issues.push({
      severity: 'warning',
      code: 'encoding-garbage',
      message:
        'The extracted content contains excessive Unicode replacement characters, ' +
        'suggesting a character-encoding mismatch.',
    });
    return;
  }

  // Mojibake patterns (UTF-8 decoded as Latin-1)
  if (text.length < MOJIBAKE_TEXT_LIMIT) {
    const mojibakeCount = (text.match(MOJIBAKE_RE) ?? []).length;
    if (mojibakeCount >= MOJIBAKE_COUNT_THRESHOLD) {
      issues.push({
        severity: 'warning',
        code: 'encoding-garbage',
        message:
          'The extracted content shows signs of mojibake (encoding corruption). ' +
          'Characters may not display correctly.',
      });
      return;
    }
  }

  // Control characters
  const controlCount = (text.match(CONTROL_CHAR_RE) ?? []).length;
  if (text.length > 0 && controlCount / text.length > CONTROL_CHAR_RATIO) {
    issues.push({
      severity: 'warning',
      code: 'encoding-garbage',
      message:
        'The extracted content contains excessive control characters, ' +
        'suggesting binary data leaked into the text.',
    });
  }
}

function checkZeroWidthCharacters(text: string, issues: ContentIssue[]): void {
  const matches = text.match(ZERO_WIDTH_RE);
  if (matches && matches.length > ZERO_WIDTH_WARN_THRESHOLD) {
    issues.push({
      severity: 'warning',
      code: 'zero-width-chars',
      message:
        `The extracted content contains ${matches.length} zero-width or invisible Unicode characters, ` +
        'which may indicate hidden text or Unicode steganography.',
    });
  }
}

function checkInjectionAndSecrets(text: string, issues: ContentIssue[]): void {
  const checker = getSafetyChecker();

  const injectionPolicy = getInjectionPolicy();
  if (injectionPolicy !== 'allow') {
    const injection = checker.checkContentInjection(text);
    if (injection.decision !== 'allow') {
      const count = injection.matchCount;
      const blocking = injectionPolicy === 'block';
      const tail = blocking ? 'was not stored.' : 'was stored but may contain adversarial text.';
      issues.push({
        severity: blocking ? 'error' : 'warning',
        code: 'possible-prompt-injection',
        message:
          count >= 3
            ? `The extracted content matches ${count} prompt-injection patterns ` +
              '(instruction overrides, role impersonation, or delimiter escapes). ' +
              `This content has a high likelihood of containing adversarial text designed to manipulate an AI agent, and ${tail}`
            : 'The extracted content contains text that resembles a prompt-injection attempt ' +
              `(e.g. instruction overrides, system impersonation, or delimiter escapes), and ${tail}`,
      });
    }
  }

  const secretsPolicy = getSecretsPolicy();
  if (secretsPolicy !== 'allow') {
    const secrets = checker.checkContentSecrets(text);
    if (secrets.decision !== 'allow') {
      const blocking = secretsPolicy === 'block';
      issues.push({
        severity: blocking ? 'error' : 'warning',
        code: 'possible-credentials',
        message: blocking
          ? 'The extracted content appears to contain credentials or secret keys; ' +
            'ingestion rejected. Review your safety config if this is a false positive.'
          : 'The extracted content appears to contain credentials or secret keys. ' +
            'Review before using this content with any external services.',
      });
    }
  }
}

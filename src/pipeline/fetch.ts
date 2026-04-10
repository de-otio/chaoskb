/**
 * URL fetching for the content pipeline.
 *
 * Uses Node.js built-in `fetch` (available since Node 18) with
 * configurable timeout, redirect limits, and user-agent.
 *
 * Includes SSRF protection to prevent fetching from private/internal networks.
 */

import dns from 'node:dns/promises';
import { isIP } from 'node:net';
import type { PipelineConfig } from './types.js';

/** Default pipeline configuration values relevant to fetching. */
const DEFAULTS: Pick<PipelineConfig, 'fetchTimeoutMs' | 'maxRedirects' | 'userAgent'> = {
  fetchTimeoutMs: 30_000,
  maxRedirects: 5,
  userAgent: 'ChaosKB/0.1',
};

/** Maximum response body size in bytes (10 MB). */
export const MAX_RESPONSE_BYTES = 10 * 1024 * 1024;

/** Well-known cloud metadata hostnames to block. */
const BLOCKED_HOSTNAMES = new Set([
  'metadata.google.internal',
  'metadata.google.internal.',
]);

/**
 * Check if an IP address belongs to a private/reserved range.
 *
 * Blocks: loopback, RFC 1918, link-local (incl. cloud metadata 169.254.x.x),
 * IPv6 loopback, IPv6 ULA, IPv6 link-local, and unspecified addresses.
 */
function isPrivateIp(ip: string): boolean {
  // IPv4 checks
  if (isIP(ip) === 4) {
    const parts = ip.split('.').map(Number);
    const [a, b] = parts;
    if (a === 127) return true;                        // 127.0.0.0/8 loopback
    if (a === 10) return true;                         // 10.0.0.0/8
    if (a === 172 && b >= 16 && b <= 31) return true;  // 172.16.0.0/12
    if (a === 192 && b === 168) return true;           // 192.168.0.0/16
    if (a === 169 && b === 254) return true;           // 169.254.0.0/16 link-local / cloud metadata
    if (a === 0) return true;                          // 0.0.0.0/8
    return false;
  }

  // IPv6 checks
  if (isIP(ip) === 6) {
    const normalized = ip.toLowerCase();
    if (normalized === '::1') return true;                   // loopback
    if (normalized === '::') return true;                    // unspecified
    if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true; // ULA fc00::/7
    if (normalized.startsWith('fe80')) return true;          // link-local
    // IPv4-mapped IPv6 — dotted form (::ffff:127.0.0.1)
    const v4dotted = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (v4dotted) return isPrivateIp(v4dotted[1]);
    // IPv4-mapped IPv6 — hex form (::ffff:7f00:1) as normalized by URL parser
    const v4hex = normalized.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (v4hex) {
      const hi = parseInt(v4hex[1], 16);
      const lo = parseInt(v4hex[2], 16);
      const ip = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
      return isPrivateIp(ip);
    }
    return false;
  }

  return false;
}

/**
 * Validate a URL for SSRF safety before fetching.
 *
 * Rejects non-HTTP(S) schemes, private/internal IPs, and known
 * cloud metadata endpoints.
 */
export async function validateUrl(url: string): Promise<void> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid URL: ${url}`);
  }

  // Only allow http and https
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(
      `URL scheme "${parsed.protocol}" is not allowed. Only http: and https: are supported.`,
    );
  }

  const hostname = parsed.hostname;

  // Block known cloud metadata hostnames
  if (BLOCKED_HOSTNAMES.has(hostname.toLowerCase())) {
    throw new Error('URL targets a cloud metadata endpoint and cannot be fetched.');
  }

  // Strip IPv6 brackets for IP checks (URL parses [::1] with brackets)
  const bareHost = hostname.startsWith('[') && hostname.endsWith(']')
    ? hostname.slice(1, -1)
    : hostname;

  // If hostname is already an IP literal, check it directly
  if (isIP(bareHost)) {
    if (isPrivateIp(bareHost)) {
      throw new Error('URL targets a private/internal network address and cannot be fetched.');
    }
    return;
  }

  // Resolve hostname and check all resulting IPs
  let addresses: { address: string; family: number }[];
  try {
    addresses = await dns.lookup(hostname, { all: true });
  } catch {
    // DNS failure will be caught later by fetch itself
    return;
  }

  for (const addr of addresses) {
    if (isPrivateIp(addr.address)) {
      throw new Error('URL targets a private/internal network address and cannot be fetched.');
    }
  }
}

/**
 * Read a Response body with a size limit to prevent memory exhaustion.
 */
async function readResponseWithLimit(response: Response, maxBytes: number): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) {
    // Fallback for environments without streaming
    return response.text();
  }

  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        reader.cancel();
        throw new Error(
          `Response body exceeds ${maxBytes / 1024 / 1024} MB limit. ` +
          'The page is too large to ingest.',
        );
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const combined = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return new TextDecoder().decode(combined);
}

/** Result of a successful URL fetch. */
export interface FetchResult {
  /** Raw HTML body. */
  html: string;
  /** Final URL after any redirects. */
  finalUrl: string;
  /** Content-Type header value. */
  contentType: string;
}

/**
 * Fetch the HTML content of a URL.
 *
 * @param url - The URL to fetch.
 * @param config - Optional partial pipeline config overrides.
 * @returns The HTML content, final URL, and content type.
 * @throws On network errors, non-2xx status codes, or non-HTML content.
 */
export async function fetchUrl(
  url: string,
  config?: Partial<PipelineConfig>,
): Promise<FetchResult> {
  // SSRF protection: reject private/internal network targets
  if (!config?._skipSsrfCheck) {
    await validateUrl(url);
  }

  const timeoutMs = config?.fetchTimeoutMs ?? DEFAULTS.fetchTimeoutMs;
  const userAgent = config?.userAgent ?? DEFAULTS.userAgent;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    response = await fetch(url, {
      method: 'GET',
      headers: {
        'User-Agent': userAgent,
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
      signal: controller.signal,
      redirect: 'follow',
    });
  } catch (error: unknown) {
    clearTimeout(timer);
    if (error instanceof Error) {
      if (error.name === 'AbortError') {
        throw new Error(`Fetch timed out after ${timeoutMs}ms: ${url}`);
      }
      // DNS resolution failures
      if (error.cause && typeof error.cause === 'object' && 'code' in error.cause) {
        const code = (error.cause as { code?: string }).code;
        if (code === 'ENOTFOUND') {
          throw new Error(`DNS resolution failed for ${url}: host not found`);
        }
        if (code === 'ECONNREFUSED') {
          throw new Error(`Connection refused for ${url}`);
        }
        if (code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || code === 'ERR_TLS_CERT_ALTNAME_INVALID') {
          throw new Error(`TLS certificate error for ${url}: ${code}`);
        }
      }
      // TLS errors often show up in the message
      if (error.message.includes('SSL') || error.message.includes('TLS') || error.message.includes('certificate')) {
        throw new Error(`TLS error fetching ${url}: ${error.message}`);
      }
      throw new Error(`Failed to fetch ${url}: ${error.message}`);
    }
    throw new Error(`Failed to fetch ${url}: unknown error`);
  } finally {
    clearTimeout(timer);
  }

  // Check HTTP status
  if (!response.ok) {
    const status = response.status;
    if (status >= 400 && status < 500) {
      throw new Error(`HTTP ${status} Client Error for ${url}: ${response.statusText}`);
    }
    if (status >= 500) {
      throw new Error(`HTTP ${status} Server Error for ${url}: ${response.statusText}`);
    }
    throw new Error(`HTTP ${status} for ${url}: ${response.statusText}`);
  }

  // Verify content type is HTML-like
  const contentType = response.headers.get('content-type') ?? '';
  const isHtml =
    contentType.includes('text/html') ||
    contentType.includes('application/xhtml+xml') ||
    contentType.includes('application/xml');

  if (!isHtml) {
    throw new Error(
      `Non-HTML content type "${contentType}" for ${url}. Only text/html is supported.`,
    );
  }

  const html = await readResponseWithLimit(response, MAX_RESPONSE_BYTES);
  const finalUrl = response.url || url;

  return { html, finalUrl, contentType };
}

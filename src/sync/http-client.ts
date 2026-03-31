import type { ISyncHttpClient } from './types.js';
import type { SyncConfig } from './types.js';
import type { SSHSigner } from './ssh-signer.js';
import { SequenceCounter } from './sequence.js';

/** Error that indicates the request can be retried after a delay. */
export class RetryableError extends Error {
  /** Seconds to wait before retrying */
  readonly retryAfterSeconds: number;

  constructor(message: string, retryAfterSeconds: number) {
    super(message);
    this.name = 'RetryableError';
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/** Default request timeout in milliseconds. */
const REQUEST_TIMEOUT_MS = 30_000;

/**
 * HTTP client for ChaosKB server communication.
 *
 * Enforces HTTPS, signs every request with the SSH signer, and
 * provides error handling for rate-limiting and network failures.
 */
export class SyncHttpClient implements ISyncHttpClient {
  private readonly baseUrl: string;
  private readonly signer: SSHSigner;
  private readonly sequence: SequenceCounter;

  constructor(config: SyncConfig, signer: SSHSigner, sequence?: SequenceCounter) {
    this.sequence = sequence ?? new SequenceCounter();
    if (!config.endpoint.startsWith('https://')) {
      throw new Error(
        `TLS required: endpoint must start with https://, got "${config.endpoint}"`,
      );
    }
    // Strip trailing slash for clean URL joining
    this.baseUrl = config.endpoint.replace(/\/+$/, '');
    this.signer = signer;
  }

  async get(path: string): Promise<Response> {
    return this.request('GET', path);
  }

  async put(path: string, body: Uint8Array): Promise<Response> {
    return this.request('PUT', path, body);
  }

  async delete(path: string): Promise<Response> {
    return this.request('DELETE', path);
  }

  async post(path: string, body?: Uint8Array): Promise<Response> {
    return this.request('POST', path, body);
  }

  private async request(method: string, path: string, body?: Uint8Array): Promise<Response> {
    const seq = this.sequence.next();
    const result = await this.signer.signRequest(method, path, seq, body);

    const headers: Record<string, string> = {
      Authorization: result.authorization,
      'X-ChaosKB-Timestamp': result.timestamp,
      'X-ChaosKB-Sequence': String(result.sequence),
      'X-ChaosKB-PublicKey': result.publicKey,
    };

    if (body) {
      headers['Content-Type'] = 'application/octet-stream';
    }

    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    let response: Response;
    try {
      response = await fetch(url, {
        method,
        headers,
        body: body ?? undefined,
        signal: controller.signal,
      });
    } catch (error: unknown) {
      clearTimeout(timeoutId);
      if (error instanceof DOMException && error.name === 'AbortError') {
        throw new Error(`Request timed out after ${REQUEST_TIMEOUT_MS}ms: ${method} ${path}`);
      }
      throw new Error(
        `Network error: ${method} ${path}: ${error instanceof Error ? error.message : String(error)}`,
      );
    } finally {
      clearTimeout(timeoutId);
    }

    if (response.status === 401) {
      throw new Error('Authentication failed: invalid or expired SSH signature');
    }

    if (response.status === 429) {
      const retryAfterHeader = response.headers.get('Retry-After');
      const retryAfterSeconds = retryAfterHeader ? parseInt(retryAfterHeader, 10) : 60;
      throw new RetryableError(
        `Rate limited: ${method} ${path}`,
        isNaN(retryAfterSeconds) ? 60 : retryAfterSeconds,
      );
    }

    return response;
  }
}

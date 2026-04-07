import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SyncHttpClient, RetryableError } from '../http-client.js';
import type { SSHSigner } from '../ssh-signer.js';
import type { SyncConfig } from '../types.js';
import type { ISyncSequenceRepository } from '../../storage/types.js';

function createMockSigner(): SSHSigner {
  return {
    signRequest: vi.fn().mockResolvedValue({
      authorization: 'SSH-Signature c2ln',
      timestamp: '2026-03-20T10:00:00.000Z',
      sequence: 1,
      publicKey: 'dGVzdA==',
    }),
  } as unknown as SSHSigner;
}

function createMockSequence(): ISyncSequenceRepository {
  let value = 0;
  return {
    next: vi.fn().mockImplementation(() => ++value),
    peek: vi.fn().mockImplementation(() => value),
  };
}

function createMockResponse(status: number, body?: unknown, headers?: Record<string, string>): Response {
  const responseHeaders = new Headers(headers);
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: responseHeaders,
    json: vi.fn().mockResolvedValue(body),
    arrayBuffer: vi.fn().mockResolvedValue(new ArrayBuffer(0)),
    text: vi.fn().mockResolvedValue(body !== undefined ? JSON.stringify(body) : ''),
  } as unknown as Response;
}

describe('SyncHttpClient', () => {
  const httpsConfig: SyncConfig = { endpoint: 'https://api.chaoskb.com' };
  let mockSigner: SSHSigner;
  let mockSequence: ISyncSequenceRepository;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockSigner = createMockSigner();
    mockSequence = createMockSequence();
  });

  describe('TLS enforcement', () => {
    it('should reject http:// endpoints', () => {
      expect(
        () => new SyncHttpClient({ endpoint: 'http://api.chaoskb.com' }, mockSigner, mockSequence),
      ).toThrow('TLS required');
    });

    it('should accept https:// endpoints', () => {
      expect(() => new SyncHttpClient(httpsConfig, mockSigner, mockSequence)).not.toThrow();
    });

    it('should reject endpoints without protocol', () => {
      expect(
        () => new SyncHttpClient({ endpoint: 'api.chaoskb.com' }, mockSigner, mockSequence),
      ).toThrow('TLS required');
    });
  });

  describe('GET', () => {
    it('should make GET request with auth headers', async () => {
      const mockResponse = createMockResponse(200, { blobs: [] });
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(mockResponse);

      const client = new SyncHttpClient(httpsConfig, mockSigner, mockSequence);
      const response = await client.get('/v1/blobs');

      expect(fetchSpy).toHaveBeenCalledWith(
        'https://api.chaoskb.com/v1/blobs',
        expect.objectContaining({
          method: 'GET',
          headers: expect.objectContaining({
            Authorization: expect.stringContaining('SSH-Signature'),
          }),
        }),
      );
      expect(response.status).toBe(200);
    });
  });

  describe('PUT', () => {
    it('should make PUT request with body and content-type', async () => {
      const mockResponse = createMockResponse(201, { id: 'b_test' });
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(mockResponse);

      const client = new SyncHttpClient(httpsConfig, mockSigner, mockSequence);
      const body = new Uint8Array([1, 2, 3]);
      await client.put('/v1/blobs/b_test', body);

      expect(fetchSpy).toHaveBeenCalledWith(
        'https://api.chaoskb.com/v1/blobs/b_test',
        expect.objectContaining({
          method: 'PUT',
          headers: expect.objectContaining({
            'Content-Type': 'application/octet-stream',
          }),
          body,
        }),
      );
    });
  });

  describe('DELETE', () => {
    it('should make DELETE request with auth headers', async () => {
      const mockResponse = createMockResponse(200);
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(mockResponse);

      const client = new SyncHttpClient(httpsConfig, mockSigner, mockSequence);
      await client.delete('/v1/blobs/b_test');

      expect(fetchSpy).toHaveBeenCalledWith(
        'https://api.chaoskb.com/v1/blobs/b_test',
        expect.objectContaining({ method: 'DELETE' }),
      );
    });
  });

  describe('POST', () => {
    it('should make POST request with optional body', async () => {
      const mockResponse = createMockResponse(200);
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(mockResponse);

      const client = new SyncHttpClient(httpsConfig, mockSigner, mockSequence);
      await client.post('/v1/auth/register');

      expect(fetchSpy).toHaveBeenCalledWith(
        'https://api.chaoskb.com/v1/auth/register',
        expect.objectContaining({ method: 'POST' }),
      );
    });
  });

  describe('error handling', () => {
    it('should throw on 401 Unauthorized', async () => {
      const mockResponse = createMockResponse(401);
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(mockResponse);

      const client = new SyncHttpClient(httpsConfig, mockSigner, mockSequence);
      await expect(client.get('/v1/blobs')).rejects.toThrow('Authentication failed');
    });

    it('should throw RetryableError on 429 with Retry-After', async () => {
      const mockResponse = createMockResponse(429, {}, { 'Retry-After': '30' });
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(mockResponse);

      const client = new SyncHttpClient(httpsConfig, mockSigner, mockSequence);
      try {
        await client.get('/v1/blobs');
        expect.unreachable('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(RetryableError);
        expect((error as RetryableError).retryAfterSeconds).toBe(30);
      }
    });

    it('should default to 60s retry on 429 without Retry-After', async () => {
      const mockResponse = createMockResponse(429);
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(mockResponse);

      const client = new SyncHttpClient(httpsConfig, mockSigner, mockSequence);
      try {
        await client.get('/v1/blobs');
        expect.unreachable('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(RetryableError);
        expect((error as RetryableError).retryAfterSeconds).toBe(60);
      }
    });

    it('should throw on network error', async () => {
      vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('fetch failed'));

      const client = new SyncHttpClient(httpsConfig, mockSigner, mockSequence);
      await expect(client.get('/v1/blobs')).rejects.toThrow('Network error');
    });

    it('should throw on timeout (abort)', async () => {
      vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
        const error = new DOMException('The operation was aborted', 'AbortError');
        return Promise.reject(error);
      });

      const client = new SyncHttpClient(httpsConfig, mockSigner, mockSequence);
      await expect(client.get('/v1/blobs')).rejects.toThrow('Request timed out');
    });
  });

  describe('auth header inclusion', () => {
    it('should call signer.signRequest with correct parameters', async () => {
      const mockResponse = createMockResponse(200);
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(mockResponse);

      const client = new SyncHttpClient(httpsConfig, mockSigner, mockSequence);
      const body = new Uint8Array([10, 20]);
      await client.put('/v1/blobs/b_xyz', body);

      expect(mockSigner.signRequest).toHaveBeenCalledWith('PUT', '/v1/blobs/b_xyz', expect.any(Number), body);
    });
  });
});

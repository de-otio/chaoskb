import { describe, it, expect } from 'vitest';
import {
  parseAuthHeaders,
  verifyTimestamp,
  buildCanonicalString,
  fingerprintFromPublicKey,
  AuthError,
} from '../../lib/handler/middleware/ssh-auth.js';

describe('parseAuthHeaders', () => {
  it('should parse new SSH-Signature format', () => {
    const headers = {
      authorization: 'SSH-Signature c2lnbmF0dXJl',
      'x-chaoskb-timestamp': '2026-03-20T10:00:00Z',
      'x-chaoskb-sequence': '42',
    };
    const result = parseAuthHeaders(headers);

    expect(result.signature).toBe('c2lnbmF0dXJl');
    expect(result.timestamp).toBe('2026-03-20T10:00:00Z');
    expect(result.sequence).toBe(42);
  });

  it('should parse legacy ChaosKB-SSH format', () => {
    const headers = {
      authorization: 'ChaosKB-SSH pubkey=dGVzdA==, ts=2026-03-20T10:00:00Z, sig=c2lnbmF0dXJl',
      'x-chaoskb-sequence': '5',
    };
    const result = parseAuthHeaders(headers);

    expect(result.signature).toBe('c2lnbmF0dXJl');
    expect(result.timestamp).toBe('2026-03-20T10:00:00Z');
    expect(result.sequence).toBe(5);
  });

  it('should reject invalid authorization scheme', () => {
    const headers = { authorization: 'Bearer token123' };
    expect(() => parseAuthHeaders(headers)).toThrow(AuthError);
    expect(() => parseAuthHeaders(headers)).toThrow('Invalid authorization scheme');
  });

  it('should reject missing authorization header', () => {
    expect(() => parseAuthHeaders({})).toThrow(AuthError);
    expect(() => parseAuthHeaders({})).toThrow('Missing Authorization header');
  });

  it('should default sequence to 0 if not provided', () => {
    const headers = {
      authorization: 'SSH-Signature c2lnbmF0dXJl',
      'x-chaoskb-timestamp': '2026-03-20T10:00:00Z',
    };
    const result = parseAuthHeaders(headers);
    expect(result.sequence).toBe(0);
  });
});

describe('verifyTimestamp', () => {
  it('should accept timestamp within 30 seconds', () => {
    const now = new Date().toISOString();
    expect(() => verifyTimestamp(now)).not.toThrow();
  });

  it('should reject timestamp older than 30 seconds', () => {
    const old = new Date(Date.now() - 60 * 1000).toISOString();
    expect(() => verifyTimestamp(old)).toThrow(AuthError);
    expect(() => verifyTimestamp(old)).toThrow('Request timestamp expired');
  });

  it('should reject future timestamp beyond 30 seconds', () => {
    const future = new Date(Date.now() + 60 * 1000).toISOString();
    expect(() => verifyTimestamp(future)).toThrow(AuthError);
  });

  it('should reject invalid timestamp format', () => {
    expect(() => verifyTimestamp('not-a-date')).toThrow(AuthError);
    expect(() => verifyTimestamp('not-a-date')).toThrow('Invalid timestamp format');
  });
});

describe('buildCanonicalString', () => {
  it('should build canonical string with body and sequence', () => {
    const result = buildCanonicalString('PUT', '/v1/blobs/b_123', '2026-03-20T10:00:00Z', 42, '{"v":1}');
    const lines = result.split('\n');

    expect(lines[0]).toBe('chaoskb-auth');
    expect(lines[1]).toBe('PUT /v1/blobs/b_123');
    expect(lines[2]).toBe('2026-03-20T10:00:00Z');
    expect(lines[3]).toBe('42');
    expect(lines[4]).toHaveLength(64); // SHA-256 hex digest
  });

  it('should build canonical string without body', () => {
    const result = buildCanonicalString('GET', '/v1/blobs', '2026-03-20T10:00:00Z', 1, null);
    const lines = result.split('\n');

    expect(lines[0]).toBe('chaoskb-auth');
    expect(lines[1]).toBe('GET /v1/blobs');
    expect(lines[2]).toBe('2026-03-20T10:00:00Z');
    expect(lines[3]).toBe('1');
    expect(lines[4]).toBe('');
  });

  it('should produce different output for different sequences', () => {
    const a = buildCanonicalString('GET', '/v1/blobs', '2026-03-20T10:00:00Z', 1, null);
    const b = buildCanonicalString('GET', '/v1/blobs', '2026-03-20T10:00:00Z', 2, null);
    expect(a).not.toBe(b);
  });
});

describe('fingerprintFromPublicKey', () => {
  it('should compute a consistent fingerprint', () => {
    const fp1 = fingerprintFromPublicKey('dGVzdA==');
    const fp2 = fingerprintFromPublicKey('dGVzdA==');
    expect(fp1).toBe(fp2);
  });

  it('should produce different fingerprints for different keys', () => {
    const fp1 = fingerprintFromPublicKey('dGVzdA==');
    const fp2 = fingerprintFromPublicKey('b3RoZXI=');
    expect(fp1).not.toBe(fp2);
  });
});

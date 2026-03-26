import { describe, it, expect, vi } from 'vitest';
import { incrementalSync } from '../incremental-sync.js';
import type { ISyncHttpClient } from '../types.js';
import type { IDatabase } from '../../storage/types.js';
import { SyncStatus } from '../../storage/types.js';

function createMockClient(responses: Map<string, { status: number; body?: unknown }>): ISyncHttpClient {
  return {
    get: vi.fn().mockImplementation(async (path: string) => {
      // Try exact match first, then prefix match (longest prefix wins)
      let bestMatch: { status: number; body?: unknown } | undefined;
      let bestLength = 0;
      for (const [key, value] of responses) {
        if (path === key && key.length > bestLength) {
          bestMatch = value;
          bestLength = key.length;
        } else if (path.startsWith(key) && key.length > bestLength) {
          bestMatch = value;
          bestLength = key.length;
        }
      }
      if (bestMatch) {
        return {
          ok: bestMatch.status >= 200 && bestMatch.status < 300,
          status: bestMatch.status,
          json: () => Promise.resolve(bestMatch.body),
          arrayBuffer: () => Promise.resolve(new ArrayBuffer(8)),
        } as unknown as Response;
      }
      return { ok: false, status: 404, json: () => Promise.resolve({}) } as unknown as Response;
    }),
    put: vi.fn(),
    delete: vi.fn(),
    post: vi.fn(),
  };
}

function createMockStorage(): IDatabase {
  const syncStatusMap = new Map<string, { blobId: string; status: SyncStatus }>();
  return {
    sources: {} as IDatabase['sources'],
    chunks: {} as IDatabase['chunks'],
    embeddingIndex: {} as IDatabase['embeddingIndex'],
    syncStatus: {
      get: vi.fn().mockImplementation((blobId: string) => syncStatusMap.get(blobId) ?? null),
      set: vi.fn().mockImplementation((blobId: string, status: SyncStatus) => {
        syncStatusMap.set(blobId, { blobId, status });
      }),
      getPending: vi.fn().mockReturnValue([]),
      getByStatus: vi.fn().mockReturnValue([]),
    },
    close: vi.fn(),
  };
}

describe('incrementalSync', () => {
  it('should download new blobs', async () => {
    const responses = new Map<string, { status: number; body?: unknown }>([
      ['/v1/blobs', {
        status: 200,
        body: {
          blobs: [
            { id: 'b_new1', size: 100, ts: '2026-03-20T10:00:00Z' },
            { id: 'b_new2', size: 200, ts: '2026-03-20T10:00:01Z' },
          ],
          tombstones: [],
        },
      }],
      ['/v1/blobs/b_new1', { status: 200, body: null }],
      ['/v1/blobs/b_new2', { status: 200, body: null }],
    ]);

    const client = createMockClient(responses);
    const storage = createMockStorage();

    const result = await incrementalSync(client, storage);

    expect(result.newBlobs).toBe(2);
    expect(result.updatedBlobs).toBe(0);
    expect(result.success).toBe(true);
    expect(storage.syncStatus.set).toHaveBeenCalledWith('b_new1', SyncStatus.Synced);
    expect(storage.syncStatus.set).toHaveBeenCalledWith('b_new2', SyncStatus.Synced);
  });

  it('should use since parameter for incremental sync', async () => {
    const responses = new Map<string, { status: number; body?: unknown }>([
      ['/v1/blobs?since=', {
        status: 200,
        body: { blobs: [], tombstones: [] },
      }],
    ]);

    const client = createMockClient(responses);
    const storage = createMockStorage();

    await incrementalSync(client, storage, '2026-03-20T09:00:00Z');

    expect(client.get).toHaveBeenCalledWith(
      expect.stringContaining('/v1/blobs?since=2026-03-20T09%3A00%3A00Z'),
    );
  });

  it('should process tombstones', async () => {
    const responses = new Map<string, { status: number; body?: unknown }>([
      ['/v1/blobs', {
        status: 200,
        body: {
          blobs: [],
          tombstones: [
            { id: 'b_deleted1', deletedAt: '2026-03-20T10:00:00Z' },
          ],
        },
      }],
    ]);

    const client = createMockClient(responses);
    const storage = createMockStorage();
    // Pre-populate existing blob
    (storage.syncStatus.get as ReturnType<typeof vi.fn>).mockImplementation((id: string) =>
      id === 'b_deleted1' ? { blobId: 'b_deleted1', status: SyncStatus.Synced } : null,
    );

    const result = await incrementalSync(client, storage);

    expect(result.deletedBlobs).toBe(1);
    expect(storage.syncStatus.set).toHaveBeenCalledWith('b_deleted1', SyncStatus.PendingDelete);
  });

  it('should handle empty response', async () => {
    const responses = new Map<string, { status: number; body?: unknown }>([
      ['/v1/blobs', {
        status: 200,
        body: { blobs: [], tombstones: [] },
      }],
    ]);

    const client = createMockClient(responses);
    const storage = createMockStorage();

    const result = await incrementalSync(client, storage);

    expect(result.newBlobs).toBe(0);
    expect(result.updatedBlobs).toBe(0);
    expect(result.deletedBlobs).toBe(0);
    expect(result.success).toBe(true);
  });

  it('should handle individual blob download failures', async () => {
    const responses = new Map<string, { status: number; body?: unknown }>([
      ['/v1/blobs', {
        status: 200,
        body: {
          blobs: [
            { id: 'b_ok', size: 100, ts: '2026-03-20T10:00:00Z' },
            { id: 'b_fail', size: 200, ts: '2026-03-20T10:00:01Z' },
          ],
          tombstones: [],
        },
      }],
      ['/v1/blobs/b_ok', { status: 200, body: null }],
      ['/v1/blobs/b_fail', { status: 500, body: null }],
    ]);

    const client = createMockClient(responses);
    const storage = createMockStorage();

    const result = await incrementalSync(client, storage);

    expect(result.newBlobs).toBe(1);
    expect(result.errors.length).toBe(1);
    expect(result.errors[0].blobId).toBe('b_fail');
    expect(result.errors[0].retryable).toBe(true);
    expect(result.success).toBe(false);
  });

  it('should detect conflict when local has unsynchronized changes and remote is newer', async () => {
    const responses = new Map<string, { status: number; body?: unknown }>([
      ['/v1/blobs', {
        status: 200,
        body: {
          blobs: [{ id: 'b_conflict', size: 100, ts: '2026-03-20T12:00:00Z' }],
          tombstones: [],
        },
      }],
      ['/v1/blobs/b_conflict', { status: 200, body: null }],
    ]);

    const client = createMockClient(responses);
    const storage = createMockStorage();
    // Local has unsynchronized changes with an older timestamp
    (storage.syncStatus.get as ReturnType<typeof vi.fn>).mockImplementation((id: string) =>
      id === 'b_conflict'
        ? { blobId: 'b_conflict', status: SyncStatus.LocalOnly, lastAttempt: '2026-03-20T10:00:00Z' }
        : null,
    );

    const result = await incrementalSync(client, storage);

    expect(result.conflicts.length).toBe(1);
    expect(result.conflicts[0].resolution).toBe('remote_wins');
    expect(result.conflicts[0].blobId).toBe('b_conflict');
    expect(result.updatedBlobs).toBe(1);
    expect(storage.syncStatus.set).toHaveBeenCalledWith('b_conflict', SyncStatus.Synced);
  });

  it('should keep local version when local changes are newer', async () => {
    const responses = new Map<string, { status: number; body?: unknown }>([
      ['/v1/blobs', {
        status: 200,
        body: {
          blobs: [{ id: 'b_conflict', size: 100, ts: '2026-03-20T08:00:00Z' }],
          tombstones: [],
        },
      }],
    ]);

    const client = createMockClient(responses);
    const storage = createMockStorage();
    // Local has unsynchronized changes with a newer timestamp
    (storage.syncStatus.get as ReturnType<typeof vi.fn>).mockImplementation((id: string) =>
      id === 'b_conflict'
        ? { blobId: 'b_conflict', status: SyncStatus.LocalOnly, lastAttempt: '2026-03-20T12:00:00Z' }
        : null,
    );

    const result = await incrementalSync(client, storage);

    expect(result.conflicts.length).toBe(1);
    expect(result.conflicts[0].resolution).toBe('local_wins');
    expect(result.newBlobs).toBe(0);
    expect(result.updatedBlobs).toBe(0);
    // Should NOT have downloaded the blob
    expect(client.get).toHaveBeenCalledTimes(1); // Only the list request
  });

  it('should keep local version when remote sends tombstone for unsynchronized blob', async () => {
    const responses = new Map<string, { status: number; body?: unknown }>([
      ['/v1/blobs', {
        status: 200,
        body: {
          blobs: [],
          tombstones: [{ id: 'b_local', deletedAt: '2026-03-20T10:00:00Z' }],
        },
      }],
    ]);

    const client = createMockClient(responses);
    const storage = createMockStorage();
    // Local has unsynchronized changes
    (storage.syncStatus.get as ReturnType<typeof vi.fn>).mockImplementation((id: string) =>
      id === 'b_local'
        ? { blobId: 'b_local', status: SyncStatus.LocalOnly }
        : null,
    );

    const result = await incrementalSync(client, storage);

    expect(result.conflicts.length).toBe(1);
    expect(result.conflicts[0].resolution).toBe('local_wins');
    expect(result.conflicts[0].reason).toContain('unsynchronized');
    expect(result.deletedBlobs).toBe(0);
    // Should NOT have set PendingDelete
    expect(storage.syncStatus.set).not.toHaveBeenCalled();
  });

  it('should return failure when list request fails', async () => {
    const responses = new Map<string, { status: number; body?: unknown }>([
      ['/v1/blobs', { status: 503, body: null }],
    ]);

    const client = createMockClient(responses);
    const storage = createMockStorage();

    const result = await incrementalSync(client, storage);

    expect(result.success).toBe(false);
    expect(result.errors[0].code).toBe('LIST_FAILED');
  });
});

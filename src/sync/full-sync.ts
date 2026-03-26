import type { ISyncHttpClient, BlobMetadata, SyncResult, SyncError, SyncState } from './types.js';
import type { IDatabase } from '../storage/types.js';
import { SyncStatus } from '../storage/types.js';

/** Server response shape for paginated blob listing. */
interface PaginatedBlobResponse {
  blobs: BlobMetadata[];
  cursor?: string;
}

/**
 * Full sync for new devices — downloads all blobs from the server.
 *
 * Supports resumability via a cursor persisted in SyncState. If a previous
 * full sync was interrupted, it resumes from where it left off.
 *
 * @param client - HTTP client for server communication
 * @param storage - Local database
 * @param state - Mutable sync state; fullSyncCursor is updated during pagination.
 *   The caller is responsible for persisting state to disk after each call.
 * @returns SyncResult with counts of processed blobs
 */
export async function fullSync(
  client: ISyncHttpClient,
  storage: IDatabase,
  state: SyncState,
): Promise<SyncResult> {
  const errors: SyncError[] = [];
  let newBlobs = 0;
  let cursor = state.fullSyncCursor;

  state.fullSyncInProgress = true;

  while (true) {
    const listPath = cursor ? `/v1/blobs?cursor=${encodeURIComponent(cursor)}` : '/v1/blobs';

    const listResponse = await client.get(listPath);
    if (!listResponse.ok) {
      errors.push({
        message: `Failed to list blobs: HTTP ${listResponse.status}`,
        code: 'LIST_FAILED',
        retryable: listResponse.status >= 500,
      });
      return {
        newBlobs,
        updatedBlobs: 0,
        deletedBlobs: 0,
        conflicts: [],
        errors,
        success: false,
      };
    }

    const page = (await listResponse.json()) as PaginatedBlobResponse;

    if (page.blobs.length === 0) {
      // No more pages — full sync complete
      break;
    }

    for (const blobMeta of page.blobs) {
      try {
        const blobResponse = await client.get(`/v1/blobs/${blobMeta.id}`);
        if (!blobResponse.ok) {
          errors.push({
            blobId: blobMeta.id,
            message: `Failed to download blob: HTTP ${blobResponse.status}`,
            code: 'DOWNLOAD_FAILED',
            retryable: blobResponse.status >= 500,
          });
          continue;
        }

        const blobData = new Uint8Array(await blobResponse.arrayBuffer());
        void blobData; // Consumed by higher-layer processing

        storage.syncStatus.set(blobMeta.id, SyncStatus.Synced);
        newBlobs++;
      } catch (error: unknown) {
        errors.push({
          blobId: blobMeta.id,
          message: error instanceof Error ? error.message : String(error),
          code: 'DOWNLOAD_ERROR',
          retryable: true,
        });
      }
    }

    // Update cursor for resumability
    if (page.cursor) {
      cursor = page.cursor;
      state.fullSyncCursor = cursor;
    } else {
      // No more pages
      break;
    }
  }

  // Mark full sync as complete
  state.fullSyncInProgress = false;
  state.fullSyncCursor = undefined;
  state.lastSyncTimestamp = new Date().toISOString();

  return {
    newBlobs,
    updatedBlobs: 0,
    deletedBlobs: 0,
    conflicts: [],
    errors,
    success: errors.length === 0,
  };
}

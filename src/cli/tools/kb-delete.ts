import type { McpDependencies } from '../mcp-server.js';
import { SyncStatus } from '../../storage/types.js';

export interface KbDeleteInput {
  id: string;
}

export interface KbDeleteResult {
  id: string;
  deleted: true;
}

export async function handleKbDelete(
  input: KbDeleteInput,
  deps: McpDependencies,
): Promise<KbDeleteResult> {
  const { db, syncService } = deps;

  // 1. Verify the source exists
  const source = db.sources.getById(input.id);
  if (!source) {
    throw new Error(`Source not found: ${input.id}`);
  }

  if (source.deletedAt) {
    throw new Error(`Source already deleted: ${input.id}`);
  }

  // 2. Soft-delete the source and its chunks
  const deleted = db.sources.softDelete(input.id);
  if (!deleted) {
    throw new Error(`Failed to delete source: ${input.id}`);
  }

  // 3. Remove from embedding index
  db.embeddingIndex.remove(input.id);

  // 4. Delete blobs from sync server and update local status
  const chunks = db.chunks.getBySourceId(input.id);
  const allBlobIds = [input.id, ...chunks.map((c) => c.id)];

  if (syncService) {
    try {
      for (const blobId of allBlobIds) {
        await syncService.deleteBlob(blobId);
        db.syncStatus.set(blobId, SyncStatus.PendingDelete);
      }
    } catch {
      // Server delete failed — mark as pending for retry
      for (const blobId of allBlobIds) {
        db.syncStatus.set(blobId, SyncStatus.PendingDelete);
      }
    }
  } else {
    for (const blobId of allBlobIds) {
      db.syncStatus.set(blobId, SyncStatus.PendingDelete);
    }
  }

  return { id: input.id, deleted: true };
}

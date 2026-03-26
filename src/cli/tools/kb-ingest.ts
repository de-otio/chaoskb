import type { McpDependencies } from '../mcp-server.js';
import type { SyncStatus } from '../../storage/types.js';
import type { SourcePayload, ChunkPayload } from '../../crypto/types.js';

export interface KbIngestInput {
  url: string;
  tags?: string[];
}

export interface KbIngestResult {
  title: string;
  url: string;
  chunkCount: number;
  blobIds: string[];
}

export async function handleKbIngest(
  input: KbIngestInput,
  deps: McpDependencies,
): Promise<KbIngestResult> {
  const { db, pipeline, encryption, keys } = deps;

  // 1. Fetch and extract content from URL
  const extracted = await pipeline.fetchAndExtract(input.url);

  // 2. Chunk the extracted text
  const chunks = pipeline.chunk(extracted.content);

  // 3. Embed all chunks
  const embeddedChunks = await pipeline.embedChunks(chunks);

  // 4. Generate blob IDs
  const sourceId = encryption.generateBlobId();
  const chunkBlobIds = embeddedChunks.map(() => encryption.generateBlobId());
  const allBlobIds = [sourceId, ...chunkBlobIds];

  // 5. Encrypt source payload
  const sourcePayload: SourcePayload = {
    type: 'source',
    url: input.url,
    title: extracted.title,
    tags: input.tags,
    chunkCount: embeddedChunks.length,
    chunkIds: chunkBlobIds,
  };
  encryption.encrypt(sourcePayload, keys, 'CEK');

  // 6. Encrypt each chunk payload
  for (let i = 0; i < embeddedChunks.length; i++) {
    const ec = embeddedChunks[i];
    const chunkPayload: ChunkPayload = {
      type: 'chunk',
      sourceId,
      index: ec.index,
      model: ec.model,
      content: ec.content,
      tokenCount: ec.tokenCount,
      embedding: Array.from(ec.embedding),
    };
    encryption.encrypt(chunkPayload, keys, 'CEK');
  }

  // 7. Store source record in database
  db.sources.insert({
    id: sourceId,
    url: input.url,
    title: extracted.title,
    tags: input.tags ?? [],
    chunkCount: embeddedChunks.length,
    blobSizeBytes: extracted.byteLength,
  });

  // 8. Store chunk records with embeddings
  const chunkRecords = embeddedChunks.map((ec, _i) => ({
    sourceId,
    chunkIndex: ec.index,
    content: ec.content,
    embedding: ec.embedding,
    tokenCount: ec.tokenCount,
    model: ec.model,
  }));
  db.chunks.insertMany(chunkRecords);

  // 9. Add embeddings to in-memory index
  db.embeddingIndex.add(
    sourceId,
    embeddedChunks.map((ec) => ({
      chunkIndex: ec.index,
      embedding: ec.embedding,
    })),
  );

  // 10. Set sync status to local_only for all blobs
  for (const blobId of allBlobIds) {
    db.syncStatus.set(blobId, 'local_only' as SyncStatus);
  }

  return {
    title: extracted.title,
    url: input.url,
    chunkCount: embeddedChunks.length,
    blobIds: allBlobIds,
  };
}

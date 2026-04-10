import type { McpDependencies } from '../mcp-server.js';
import type { SourcePayload, ChunkPayload } from '../../crypto/types.js';

export interface KbIngestInput {
  url?: string;
  filePath?: string;
  tags?: string[];
}

export interface KbIngestResult {
  title: string;
  url: string;
  chunkCount: number;
  blobIds: string[];
  warnings?: string[];
}

export async function handleKbIngest(
  input: KbIngestInput,
  deps: McpDependencies,
): Promise<KbIngestResult> {
  const { db, pipeline, encryption, keys } = deps;
  const ingestWarnings: string[] = [];

  // Validate: exactly one of url or filePath
  if (!input.url && !input.filePath) {
    throw new Error('Either url or filePath must be provided.');
  }
  if (input.url && input.filePath) {
    throw new Error('Provide either url or filePath, not both.');
  }

  const sourceIdentifier = (input.url ?? input.filePath)!;

  // 0. Check for duplicate source (warn but don't block)
  const existing = db.sources.getByUrl(sourceIdentifier);
  if (existing) {
    ingestWarnings.push(
      `[duplicate-source] This source was already ingested on ${existing.createdAt} (source: ${existing.id}). ` +
      'Ingesting again creates a duplicate entry.',
    );
  }

  // 1. Extract content (dispatch based on input type)
  let extracted;
  try {
    extracted = input.filePath
      ? await pipeline.extractFromFile(input.filePath)
      : await pipeline.fetchAndExtract(input.url!);
  } catch (error: unknown) {
    if (input.url && error instanceof Error) {
      const msg = error.message;
      const isBotBlock =
        msg.includes('anti-bot') ||
        msg.includes('CAPTCHA') ||
        msg.includes('JavaScript to render') ||
        msg.includes('Access Denied') ||
        msg.includes('bot-detection');
      if (isBotBlock) {
        throw new Error(
          msg +
          '\n\nTip: Save the page as PDF in your browser (Print → Save as PDF), ' +
          'then ingest the file using the filepath instead of the url.',
        );
      }
    }
    throw error;
  }

  if (extracted.warnings) {
    ingestWarnings.push(...extracted.warnings);
  }

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
    url: sourceIdentifier,
    title: extracted.title,
    tags: input.tags,
    chunkCount: embeddedChunks.length,
    chunkIds: chunkBlobIds,
  };
  const sourceEncrypted = encryption.encrypt(sourcePayload, keys, 'CEK');

  // 6. Encrypt each chunk payload
  const chunkEncrypted: Array<{ blobId: string; bytes: Uint8Array }> = [];
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
    const result = encryption.encrypt(chunkPayload, keys, 'CEK');
    chunkEncrypted.push({ blobId: chunkBlobIds[i], bytes: result.bytes });
  }

  // 7. Store source record in database
  db.sources.insert({
    id: sourceId,
    url: sourceIdentifier,
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

  // 10. Enqueue encrypted blobs for sync (queue processor handles upload)
  db.storeAndEnqueueUpload(sourceId, sourceEncrypted.bytes);
  for (const chunk of chunkEncrypted) {
    db.storeAndEnqueueUpload(chunk.blobId, chunk.bytes);
  }

  return {
    title: extracted.title,
    url: sourceIdentifier,
    chunkCount: embeddedChunks.length,
    blobIds: allBlobIds,
    ...(ingestWarnings.length > 0 ? { warnings: ingestWarnings } : {}),
  };
}

import type BetterSqlite3 from 'better-sqlite3';
import * as crypto from 'node:crypto';
import type { IChunkRepository, ChunkRecord } from './types.js';

interface ChunkRow {
  id: string;
  source_id: string;
  chunk_index: number;
  content: string;
  embedding: Buffer | null;
  token_count: number;
  model: string;
}

function rowToRecord(row: ChunkRow): ChunkRecord {
  let embedding: Float32Array;
  if (row.embedding) {
    // Buffer → Float32Array
    const uint8 = new Uint8Array(row.embedding);
    embedding = new Float32Array(uint8.buffer, uint8.byteOffset, uint8.byteLength / 4);
  } else {
    embedding = new Float32Array(0);
  }

  return {
    id: row.id,
    sourceId: row.source_id,
    chunkIndex: row.chunk_index,
    content: row.content,
    embedding,
    tokenCount: row.token_count,
    model: row.model,
  };
}

/** Result of a keyword search using FTS5 */
export interface KeywordSearchResult {
  sourceId: string;
  chunkIndex: number;
  content: string;
  snippet: string;
  rank: number;
}

export class ChunkRepository implements IChunkRepository {
  private readonly db: BetterSqlite3.Database;

  private readonly insertStmt: BetterSqlite3.Statement;
  private readonly getBySourceIdStmt: BetterSqlite3.Statement;
  private readonly deleteBySourceIdStmt: BetterSqlite3.Statement;

  constructor(db: BetterSqlite3.Database) {
    this.db = db;

    this.insertStmt = db.prepare(`
      INSERT INTO chunks (id, source_id, chunk_index, content, embedding, token_count, model)
      VALUES (@id, @sourceId, @chunkIndex, @content, @embedding, @tokenCount, @model)
    `);

    this.getBySourceIdStmt = db.prepare(
      'SELECT * FROM chunks WHERE source_id = ? ORDER BY chunk_index ASC',
    );

    this.deleteBySourceIdStmt = db.prepare('DELETE FROM chunks WHERE source_id = ?');
  }

  insertMany(chunks: Omit<ChunkRecord, 'id'>[]): ChunkRecord[] {
    const results: ChunkRecord[] = [];

    const insertAll = this.db.transaction(() => {
      for (const chunk of chunks) {
        const id = crypto.randomUUID();

        let embeddingBuf: Buffer | null = null;
        if (chunk.embedding && chunk.embedding.length > 0) {
          embeddingBuf = Buffer.from(
            chunk.embedding.buffer,
            chunk.embedding.byteOffset,
            chunk.embedding.byteLength,
          );
        }

        this.insertStmt.run({
          id,
          sourceId: chunk.sourceId,
          chunkIndex: chunk.chunkIndex,
          content: chunk.content,
          embedding: embeddingBuf,
          tokenCount: chunk.tokenCount,
          model: chunk.model,
        });

        results.push({
          id,
          sourceId: chunk.sourceId,
          chunkIndex: chunk.chunkIndex,
          content: chunk.content,
          embedding: chunk.embedding,
          tokenCount: chunk.tokenCount,
          model: chunk.model,
        });
      }
    });

    insertAll();
    return results;
  }

  getBySourceId(sourceId: string): ChunkRecord[] {
    const rows = this.getBySourceIdStmt.all(sourceId) as ChunkRow[];
    return rows.map(rowToRecord);
  }

  deleteBySourceId(sourceId: string): number {
    const result = this.deleteBySourceIdStmt.run(sourceId);
    return result.changes;
  }

  /**
   * Search chunk content using FTS5 keyword matching.
   *
   * @param query - Search query (supports FTS5 syntax: AND, OR, NOT, "phrase", prefix*)
   * @param topK - Maximum number of results to return.
   * @returns Results ranked by BM25 relevance score.
   */
  searchKeyword(query: string, topK: number): KeywordSearchResult[] {
    if (!query || query.trim().length === 0) {
      return [];
    }

    try {
      const stmt = this.db.prepare(`
        SELECT
          chunks_fts.source_id,
          chunks_fts.chunk_index,
          chunks_fts.content,
          snippet(chunks_fts, 0, '>>>>', '<<<<', '...', 32) AS snippet,
          rank
        FROM chunks_fts
        WHERE chunks_fts MATCH ?
        ORDER BY rank
        LIMIT ?
      `);

      const rows = stmt.all(query, topK) as Array<{
        source_id: string;
        chunk_index: number;
        content: string;
        snippet: string;
        rank: number;
      }>;

      return rows.map((row) => ({
        sourceId: row.source_id,
        chunkIndex: row.chunk_index,
        content: row.content,
        snippet: row.snippet,
        rank: row.rank,
      }));
    } catch {
      // FTS5 query syntax errors should not crash — return empty results
      return [];
    }
  }
}

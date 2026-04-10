import type { McpDependencies } from '../mcp-server.js';

/**
 * Wrap a chunk's content with source attribution delimiters.
 * This makes trust boundaries visible per-chunk when content is served to an AI agent.
 */
function wrapChunkContent(content: string, title: string, url: string): string {
  return `[Source: "${title}" from ${url} — UNTRUSTED CONTENT]\n${content}\n[/Source]`;
}

export interface KbQueryInput {
  query: string;
  limit?: number;
  mode?: 'semantic' | 'keyword' | 'hybrid';
}

export interface KbQueryResultItem {
  sourceId: string;
  title: string;
  url: string;
  content: string;
  score: number;
  chunkIndex: number;
  /** Timestamp when the source was ingested */
  ingestedAt: string;
}

export interface KbQueryResult {
  results: KbQueryResultItem[];
  mode: string;
}

export async function handleKbQuery(
  input: KbQueryInput,
  deps: McpDependencies,
): Promise<KbQueryResult> {
  const limit = input.limit ?? 10;
  const mode = input.mode ?? 'semantic';

  if (mode === 'keyword') {
    return keywordSearch(input.query, limit, deps);
  }

  if (mode === 'hybrid') {
    return hybridSearch(input.query, limit, deps);
  }

  // Default: semantic search
  return semanticSearch(input.query, limit, deps);
}

async function semanticSearch(
  query: string,
  limit: number,
  deps: McpDependencies,
): Promise<KbQueryResult> {
  const { db, pipeline } = deps;

  // 1. Embed the query using the pipeline embedder
  const queryEmbedding = await pipeline.embed(query);

  // 2. Search the embedding index for top-K matches
  const matches = db.embeddingIndex.search(queryEmbedding, limit);

  // 3. For each match, load the chunk content and source metadata
  const results: KbQueryResultItem[] = [];
  for (const match of matches) {
    const source = db.sources.getById(match.sourceId);
    if (!source || source.deletedAt) continue;

    const chunks = db.chunks.getBySourceId(match.sourceId);
    const chunk = chunks.find((c) => c.chunkIndex === match.chunkIndex);
    if (!chunk) continue;

    // Update last accessed timestamp
    db.sources.updateLastAccessed(match.sourceId);

    results.push({
      sourceId: match.sourceId,
      title: source.title,
      url: source.url,
      content: wrapChunkContent(chunk.content, source.title, source.url),
      score: match.score,
      chunkIndex: match.chunkIndex,
      ingestedAt: source.createdAt,
    });
  }

  return { results, mode: 'semantic' };
}

async function keywordSearch(
  query: string,
  limit: number,
  deps: McpDependencies,
): Promise<KbQueryResult> {
  const { db } = deps;

  const matches = db.chunks.searchKeyword(query, limit);

  const results: KbQueryResultItem[] = [];
  for (const match of matches) {
    const source = db.sources.getById(match.sourceId);
    if (!source || source.deletedAt) continue;

    db.sources.updateLastAccessed(match.sourceId);

    results.push({
      sourceId: match.sourceId,
      title: source.title,
      url: source.url,
      content: wrapChunkContent(match.snippet, source.title, source.url),
      score: -match.rank, // FTS5 rank is negative (lower = better), flip for consistency
      chunkIndex: match.chunkIndex,
      ingestedAt: source.createdAt,
    });
  }

  return { results, mode: 'keyword' };
}

async function hybridSearch(
  query: string,
  limit: number,
  deps: McpDependencies,
): Promise<KbQueryResult> {
  // Run both searches with 2x limit to ensure we have enough after deduplication
  const [semanticResults, keywordResults] = await Promise.all([
    semanticSearch(query, limit * 2, deps),
    keywordSearch(query, limit * 2, deps),
  ]);

  // Normalize scores to [0, 1] range for merging
  const semanticMax = Math.max(...semanticResults.results.map((r) => r.score), 0.001);
  const keywordMax = Math.max(...keywordResults.results.map((r) => r.score), 0.001);

  // Build combined score map: key = sourceId:chunkIndex
  const combined = new Map<string, KbQueryResultItem & { combinedScore: number }>();

  const SEMANTIC_WEIGHT = 0.7;
  const KEYWORD_WEIGHT = 0.3;

  for (const r of semanticResults.results) {
    const key = `${r.sourceId}:${r.chunkIndex}`;
    const normScore = r.score / semanticMax;
    combined.set(key, {
      ...r,
      combinedScore: normScore * SEMANTIC_WEIGHT,
    });
  }

  for (const r of keywordResults.results) {
    const key = `${r.sourceId}:${r.chunkIndex}`;
    const normScore = r.score / keywordMax;
    const existing = combined.get(key);
    if (existing) {
      // Boost: this chunk appeared in both searches
      existing.combinedScore += normScore * KEYWORD_WEIGHT;
      // Prefer semantic content over keyword snippet
    } else {
      combined.set(key, {
        ...r,
        combinedScore: normScore * KEYWORD_WEIGHT,
      });
    }
  }

  // Sort by combined score and take top-K
  const sorted = [...combined.values()]
    .sort((a, b) => b.combinedScore - a.combinedScore)
    .slice(0, limit);

  const results: KbQueryResultItem[] = sorted.map(({ combinedScore, ...rest }) => ({
    ...rest,
    score: combinedScore,
  }));

  return { results, mode: 'hybrid' };
}

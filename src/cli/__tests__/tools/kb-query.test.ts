import { describe, it, expect, vi, beforeEach } from 'vitest';
import { handleKbQuery } from '../../tools/kb-query.js';
import { createMockDeps } from '../mcp-server.test.js';
import type { McpDependencies } from '../../mcp-server.js';

describe('kb-query handler', () => {
  let deps: McpDependencies;

  beforeEach(() => {
    deps = createMockDeps();
  });

  it('should return search results with content', async () => {
    vi.mocked(deps.pipeline.embed).mockResolvedValue(new Float32Array(384));
    vi.mocked(deps.db.embeddingIndex.search).mockReturnValue([
      { sourceId: 'src1', chunkIndex: 0, score: 0.95 },
      { sourceId: 'src2', chunkIndex: 1, score: 0.87 },
    ]);
    vi.mocked(deps.db.sources.getById).mockImplementation((id: string) => {
      if (id === 'src1') {
        return {
          id: 'src1',
          url: 'https://example.com/1',
          title: 'First Article',
          tags: ['ai'],
          chunkCount: 3,
          blobSizeBytes: 1000,
          createdAt: '2026-03-01T00:00:00Z',
          updatedAt: '2026-03-01T00:00:00Z',
          lastAccessedAt: '2026-03-01T00:00:00Z',
        };
      }
      if (id === 'src2') {
        return {
          id: 'src2',
          url: 'https://example.com/2',
          title: 'Second Article',
          tags: [],
          chunkCount: 5,
          blobSizeBytes: 2000,
          createdAt: '2026-03-02T00:00:00Z',
          updatedAt: '2026-03-02T00:00:00Z',
          lastAccessedAt: '2026-03-02T00:00:00Z',
        };
      }
      return null;
    });
    vi.mocked(deps.db.chunks.getBySourceId).mockImplementation((sourceId: string) => {
      if (sourceId === 'src1') {
        return [
          {
            id: 'c1',
            sourceId: 'src1',
            chunkIndex: 0,
            content: 'First chunk content',
            embedding: new Float32Array(384),
            tokenCount: 3,
            model: 'snowflake-arctic-embed-s@384',
          },
        ];
      }
      if (sourceId === 'src2') {
        return [
          {
            id: 'c2',
            sourceId: 'src2',
            chunkIndex: 0,
            content: 'Second chunk zero',
            embedding: new Float32Array(384),
            tokenCount: 3,
            model: 'snowflake-arctic-embed-s@384',
          },
          {
            id: 'c3',
            sourceId: 'src2',
            chunkIndex: 1,
            content: 'Second chunk one',
            embedding: new Float32Array(384),
            tokenCount: 3,
            model: 'snowflake-arctic-embed-s@384',
          },
        ];
      }
      return [];
    });

    const result = await handleKbQuery({ query: 'test query' }, deps);

    expect(result.results).toHaveLength(2);
    expect(result.results[0]).toEqual({
      sourceId: 'src1',
      title: 'First Article',
      url: 'https://example.com/1',
      content: '[Source: "First Article" from https://example.com/1 — UNTRUSTED CONTENT]\nFirst chunk content\n[/Source]',
      score: 0.95,
      chunkIndex: 0,
      ingestedAt: '2026-03-01T00:00:00Z',
    });
    expect(result.results[1]).toEqual({
      sourceId: 'src2',
      title: 'Second Article',
      url: 'https://example.com/2',
      content: '[Source: "Second Article" from https://example.com/2 — UNTRUSTED CONTENT]\nSecond chunk one\n[/Source]',
      score: 0.87,
      chunkIndex: 1,
      ingestedAt: '2026-03-02T00:00:00Z',
    });
  });

  it('should return empty results when no matches', async () => {
    vi.mocked(deps.pipeline.embed).mockResolvedValue(new Float32Array(384));
    vi.mocked(deps.db.embeddingIndex.search).mockReturnValue([]);

    const result = await handleKbQuery({ query: 'no matches' }, deps);

    expect(result.results).toHaveLength(0);
  });

  it('should use default limit of 10', async () => {
    vi.mocked(deps.pipeline.embed).mockResolvedValue(new Float32Array(384));
    vi.mocked(deps.db.embeddingIndex.search).mockReturnValue([]);

    await handleKbQuery({ query: 'test' }, deps);

    expect(deps.db.embeddingIndex.search).toHaveBeenCalledWith(
      expect.any(Float32Array),
      10,
    );
  });

  it('should use custom limit when provided', async () => {
    vi.mocked(deps.pipeline.embed).mockResolvedValue(new Float32Array(384));
    vi.mocked(deps.db.embeddingIndex.search).mockReturnValue([]);

    await handleKbQuery({ query: 'test', limit: 5 }, deps);

    expect(deps.db.embeddingIndex.search).toHaveBeenCalledWith(
      expect.any(Float32Array),
      5,
    );
  });

  it('should return keyword search results', async () => {
    vi.mocked(deps.db.chunks.searchKeyword).mockReturnValue([
      { sourceId: 'src1', chunkIndex: 0, content: 'Full content', snippet: 'keyword snippet', rank: -5 },
    ]);
    vi.mocked(deps.db.sources.getById).mockReturnValue({
      id: 'src1',
      url: 'https://example.com/1',
      title: 'Keyword Article',
      tags: [],
      chunkCount: 1,
      blobSizeBytes: 500,
      createdAt: '2026-03-01T00:00:00Z',
      updatedAt: '2026-03-01T00:00:00Z',
      lastAccessedAt: '2026-03-01T00:00:00Z',
    });

    const result = await handleKbQuery({ query: 'test', mode: 'keyword' }, deps);

    expect(result.mode).toBe('keyword');
    expect(result.results).toHaveLength(1);
    expect(result.results[0].content).toContain('keyword snippet');
    expect(result.results[0].content).toContain('[Source:');
    expect(result.results[0].ingestedAt).toBe('2026-03-01T00:00:00Z');
    expect(result.results[0].score).toBe(5); // flipped from -5
  });

  it('should return hybrid search results merging semantic and keyword', async () => {
    vi.mocked(deps.pipeline.embed).mockResolvedValue(new Float32Array(384));
    vi.mocked(deps.db.embeddingIndex.search).mockReturnValue([
      { sourceId: 'src1', chunkIndex: 0, score: 0.9 },
    ]);
    vi.mocked(deps.db.chunks.searchKeyword).mockReturnValue([
      { sourceId: 'src1', chunkIndex: 0, content: 'Full content', snippet: 'keyword match', rank: -3 },
      { sourceId: 'src2', chunkIndex: 0, content: 'Other content', snippet: 'other keyword', rank: -1 },
    ]);
    vi.mocked(deps.db.sources.getById).mockImplementation((id: string) => {
      if (id === 'src1') {
        return {
          id: 'src1', url: 'https://example.com/1', title: 'Article One',
          tags: [], chunkCount: 1, blobSizeBytes: 500,
          createdAt: '2026-03-01T00:00:00Z', updatedAt: '2026-03-01T00:00:00Z',
          lastAccessedAt: '2026-03-01T00:00:00Z',
        };
      }
      if (id === 'src2') {
        return {
          id: 'src2', url: 'https://example.com/2', title: 'Article Two',
          tags: [], chunkCount: 1, blobSizeBytes: 500,
          createdAt: '2026-03-02T00:00:00Z', updatedAt: '2026-03-02T00:00:00Z',
          lastAccessedAt: '2026-03-02T00:00:00Z',
        };
      }
      return null;
    });
    vi.mocked(deps.db.chunks.getBySourceId).mockImplementation((sourceId: string) => {
      if (sourceId === 'src1') {
        return [{
          id: 'c1', sourceId: 'src1', chunkIndex: 0,
          content: 'Semantic content', embedding: new Float32Array(384),
          tokenCount: 3, model: 'snowflake-arctic-embed-s@384',
        }];
      }
      return [];
    });

    const result = await handleKbQuery({ query: 'test', mode: 'hybrid' }, deps);

    expect(result.mode).toBe('hybrid');
    expect(result.results.length).toBeGreaterThanOrEqual(1);
    // src1 should appear in both searches and get boosted
    const src1Result = result.results.find((r) => r.sourceId === 'src1');
    expect(src1Result).toBeDefined();
    expect(src1Result!.ingestedAt).toBe('2026-03-01T00:00:00Z');
  });

  it('should skip deleted sources', async () => {
    vi.mocked(deps.pipeline.embed).mockResolvedValue(new Float32Array(384));
    vi.mocked(deps.db.embeddingIndex.search).mockReturnValue([
      { sourceId: 'deleted-src', chunkIndex: 0, score: 0.9 },
    ]);
    vi.mocked(deps.db.sources.getById).mockReturnValue({
      id: 'deleted-src',
      url: 'https://example.com/deleted',
      title: 'Deleted',
      tags: [],
      chunkCount: 1,
      blobSizeBytes: 100,
      createdAt: '2026-03-01T00:00:00Z',
      updatedAt: '2026-03-01T00:00:00Z',
      lastAccessedAt: '2026-03-01T00:00:00Z',
      deletedAt: '2026-03-15T00:00:00Z',
    });

    const result = await handleKbQuery({ query: 'test' }, deps);

    expect(result.results).toHaveLength(0);
  });
});

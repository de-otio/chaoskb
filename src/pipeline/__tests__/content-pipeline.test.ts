import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, it, expect, vi } from 'vitest';
import type { Chunk, EmbeddingVector } from '../types.js';

const fetchUrlMock = vi.fn();
const fetchUrlWithBrowserMock = vi.fn();

vi.mock('../fetch.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../fetch.js')>();
  return { ...actual, fetchUrl: fetchUrlMock };
});

vi.mock('../fetch-browser.js', () => ({
  fetchUrlWithBrowser: fetchUrlWithBrowserMock,
}));

const { ContentPipeline } = await import('../content-pipeline.js');

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, 'fixtures');
function fixture(name: string): string {
  return join(FIXTURES_DIR, name);
}

/** Create a mock Embedder with controllable embed/embedBatch. */
function createMockEmbedder() {
  const dim = 384;
  const fakeVector = (): EmbeddingVector => {
    const v = new Float32Array(dim);
    v[0] = 1; // simple non-zero vector
    return v;
  };

  return {
    embed: vi.fn(async (_text: string) => fakeVector()),
    embedBatch: vi.fn(async (texts: string[]) => texts.map(() => fakeVector())),
    initialize: vi.fn(async () => {}),
    dispose: vi.fn(),
    modelPath: '/fake/model.onnx',
  };
}

describe('ContentPipeline', () => {
  it('chunk delegates to chunkText with configured options', () => {
    const embedder = createMockEmbedder();
    const pipeline = new ContentPipeline(
      { maxChunkTokens: 100, overlapTokens: 10 },
      embedder as never,
    );

    const text = 'Hello world. This is a test sentence. Another one here.';
    const chunks = pipeline.chunk(text);

    expect(Array.isArray(chunks)).toBe(true);
    expect(chunks.length).toBeGreaterThanOrEqual(1);
    expect(chunks[0]).toHaveProperty('content');
    expect(chunks[0]).toHaveProperty('index');
    expect(chunks[0]).toHaveProperty('tokenCount');
    expect(chunks[0]).toHaveProperty('byteOffset');
  });

  it('search returns indices of top-K results', () => {
    const embedder = createMockEmbedder();
    const pipeline = new ContentPipeline({}, embedder as never);

    const query = new Float32Array([1, 0, 0]);
    const embeddings: EmbeddingVector[] = [
      new Float32Array([0, 1, 0]),
      new Float32Array([1, 0, 0]),
      new Float32Array([0, 0, 1]),
    ];

    const indices = pipeline.search(query, embeddings, 2);

    expect(indices).toHaveLength(2);
    // The most similar (index 1 = identical) should be first
    expect(indices[0]).toBe(1);
    // All returned values should be numbers
    indices.forEach((idx) => expect(typeof idx).toBe('number'));
  });

  it('embedChunks zips embeddings with chunk data', async () => {
    const embedder = createMockEmbedder();
    const pipeline = new ContentPipeline({}, embedder as never);

    const chunks: Chunk[] = [
      { content: 'first chunk', index: 0, tokenCount: 5, byteOffset: 0 },
      { content: 'second chunk', index: 1, tokenCount: 6, byteOffset: 12 },
    ];

    const result = await pipeline.embedChunks(chunks);

    expect(result).toHaveLength(2);
    expect(embedder.embedBatch).toHaveBeenCalledWith(['first chunk', 'second chunk']);

    // Each result preserves chunk fields and adds embedding + model
    expect(result[0].content).toBe('first chunk');
    expect(result[0].index).toBe(0);
    expect(result[0].model).toBe('snowflake-arctic-embed-s@384');
    expect(result[0].embedding).toBeInstanceOf(Float32Array);
    expect(result[0].embedding.length).toBe(384);

    expect(result[1].content).toBe('second chunk');
    expect(result[1].index).toBe(1);
    expect(result[1].model).toBe('snowflake-arctic-embed-s@384');
  });

  it('embed delegates to the injected embedder', async () => {
    const embedder = createMockEmbedder();
    const pipeline = new ContentPipeline({}, embedder as never);

    const vec = await pipeline.embed('test text');

    expect(embedder.embed).toHaveBeenCalledWith('test text');
    expect(vec).toBeInstanceOf(Float32Array);
  });

  describe('extractFromFile', () => {
    it('extracts content from a text file', async () => {
      const embedder = createMockEmbedder();
      const pipeline = new ContentPipeline({}, embedder as never);
      const result = await pipeline.extractFromFile(fixture('sample.txt'));
      expect(result.content).toContain('Functional programming');
      expect(result.title).toBe('Functional Programming Fundamentals');
    });

    it('extracts content from a PDF file', { timeout: 30_000 }, async () => {
      const embedder = createMockEmbedder();
      const pipeline = new ContentPipeline({}, embedder as never);
      const result = await pipeline.extractFromFile(fixture('sample.pdf'));
      expect(result.content).toContain('Climate');
    });

    it('throws on unsupported format', async () => {
      const embedder = createMockEmbedder();
      const pipeline = new ContentPipeline({}, embedder as never);
      await expect(pipeline.extractFromFile('/path/to/file.xyz')).rejects.toThrow(
        'Unsupported file format',
      );
    });

    it('does not attach warnings for healthy content', async () => {
      const embedder = createMockEmbedder();
      const pipeline = new ContentPipeline({}, embedder as never);
      const result = await pipeline.extractFromFile(fixture('sample.txt'));
      expect(result.warnings).toBeUndefined();
    });

    it('throws validation error for thin content files', async () => {
      const { writeFileSync } = await import('node:fs');
      const { tmpdir } = await import('node:os');
      const { join } = await import('node:path');
      const tmpFile = join(tmpdir(), 'chaoskb-thin.txt');
      writeFileSync(tmpFile, 'Tiny.');
      const embedder = createMockEmbedder();
      const pipeline = new ContentPipeline({}, embedder as never);
      await expect(pipeline.extractFromFile(tmpFile)).rejects.toThrow('too short');
    });

    it('attaches warnings for short content files', async () => {
      const { writeFileSync } = await import('node:fs');
      const { tmpdir } = await import('node:os');
      const { join } = await import('node:path');
      const tmpFile = join(tmpdir(), 'chaoskb-short.txt');
      // 100 chars — above thin (50) but below short threshold (200)
      writeFileSync(tmpFile, 'A'.repeat(100));
      const embedder = createMockEmbedder();
      const pipeline = new ContentPipeline({}, embedder as never);
      const result = await pipeline.extractFromFile(tmpFile);
      expect(result.warnings).toBeDefined();
      expect(result.warnings!.some((w) => w.includes('short-content'))).toBe(true);
    });
  });

  describe('fetchAndExtract JS-render fallback', () => {
    const spaHtml = `
      <html><head><title>SPA</title></head>
      <body>
        <noscript>Please enable JavaScript to view this site.</noscript>
        <div id="root"></div>
        <script src="/bundle.js"></script>
      </body></html>
    `;

    const renderedHtml = `
      <html><head><title>Rendered Page</title></head>
      <body><article>
        <h1>Rendered Page</h1>
        <p>${'This is the post-render article body. '.repeat(30)}</p>
      </article></body></html>
    `;

    beforeEach(() => {
      fetchUrlMock.mockReset();
      fetchUrlWithBrowserMock.mockReset();
    });

    afterEach(() => {
      fetchUrlMock.mockReset();
      fetchUrlWithBrowserMock.mockReset();
    });

    it('falls back to browser render when raw HTML is a JS-only shell', async () => {
      fetchUrlMock.mockResolvedValue({
        html: spaHtml,
        finalUrl: 'https://example.com/spa',
        contentType: 'text/html',
      });
      fetchUrlWithBrowserMock.mockResolvedValue(renderedHtml);

      const embedder = createMockEmbedder();
      const pipeline = new ContentPipeline(
        { _skipSafetyCheck: true } as never,
        embedder as never,
      );
      const result = await pipeline.fetchAndExtract('https://example.com/spa');

      expect(fetchUrlWithBrowserMock).toHaveBeenCalledWith('https://example.com/spa');
      expect(result.content).toContain('post-render article body');
    });

    it('does not invoke browser fallback for normal article pages', async () => {
      fetchUrlMock.mockResolvedValue({
        html: renderedHtml,
        finalUrl: 'https://example.com/article',
        contentType: 'text/html',
      });

      const embedder = createMockEmbedder();
      const pipeline = new ContentPipeline(
        { _skipSafetyCheck: true } as never,
        embedder as never,
      );
      await pipeline.fetchAndExtract('https://example.com/article');

      expect(fetchUrlWithBrowserMock).not.toHaveBeenCalled();
    });

    it('propagates JsRenderRequiredError if render still yields an SPA shell', async () => {
      fetchUrlMock.mockResolvedValue({
        html: spaHtml,
        finalUrl: 'https://example.com/spa',
        contentType: 'text/html',
      });
      // Simulated: the headless render returns another SPA shell.
      fetchUrlWithBrowserMock.mockResolvedValue(spaHtml);

      const embedder = createMockEmbedder();
      const pipeline = new ContentPipeline(
        { _skipSafetyCheck: true } as never,
        embedder as never,
      );
      await expect(
        pipeline.fetchAndExtract('https://example.com/spa'),
      ).rejects.toThrow(/require JavaScript/);
    });
  });
});

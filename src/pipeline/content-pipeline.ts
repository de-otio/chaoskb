import { chunkText } from './chunker.js';
import type { Embedder } from './embedder.js';
import { extractContent, JsRenderRequiredError } from './extract.js';
import { extractFromFile as fileExtract } from './file-extract.js';
import { fetchUrl } from './fetch.js';
import { fetchUrlWithBrowser } from './fetch-browser.js';
import { getSafetyChecker } from './safety.js';
import { searchEmbeddings } from './search.js';
import { validateContent, validateFileContent } from './validate.js';
import type {
  Chunk,
  EmbeddedChunk,
  EmbeddingVector,
  ExtractedContent,
  IContentPipeline,
  PipelineConfig,
} from './types.js';

/**
 * Concrete implementation of IContentPipeline.
 *
 * Orchestrates fetching, extraction, chunking, embedding, and search
 * by delegating to the standalone pipeline functions and an injected Embedder.
 */
export class ContentPipeline implements IContentPipeline {
  private readonly config: Partial<PipelineConfig>;
  private readonly embedder: Embedder;

  constructor(config: Partial<PipelineConfig>, embedder: Embedder) {
    this.config = config;
    this.embedder = embedder;
  }

  /** Fetch a URL and extract its main article content. */
  async fetchAndExtract(url: string): Promise<ExtractedContent> {
    if (!this.config._skipSafetyCheck) {
      const urlCheck = await getSafetyChecker().checkUrl(url);
      if (urlCheck.decision !== 'allow') {
        throw new Error(`URL blocked: ${urlCheck.reason ?? urlCheck.decision}`);
      }
    }

    const result = await fetchUrl(url, this.config);

    let html = result.html;
    let extracted: ExtractedContent;
    try {
      extracted = extractContent(html, result.finalUrl);
    } catch (err) {
      if (err instanceof JsRenderRequiredError) {
        // JavaScript-rendered page: re-fetch through headless Chromium and
        // run the same extraction pipeline on the post-render HTML.
        html = await fetchUrlWithBrowser(result.finalUrl);
        extracted = extractContent(html, result.finalUrl);
      } else {
        throw err;
      }
    }

    const issues = validateContent(html, extracted);

    const errors = issues.filter((i) => i.severity === 'error');
    if (errors.length > 0) {
      throw new Error(errors.map((e) => e.message).join('; '));
    }

    const warns = issues.filter((i) => i.severity === 'warning');
    if (warns.length > 0) {
      extracted.warnings = warns.map((w) => `[${w.code}] ${w.message}`);
    }

    return extracted;
  }

  /** Extract content from a local file. */
  async extractFromFile(filePath: string): Promise<ExtractedContent> {
    const extracted = await fileExtract(filePath);

    const issues = validateFileContent(extracted);

    const errors = issues.filter((i) => i.severity === 'error');
    if (errors.length > 0) {
      throw new Error(errors.map((e) => e.message).join('; '));
    }

    const warns = issues.filter((i) => i.severity === 'warning');
    if (warns.length > 0) {
      extracted.warnings = warns.map((w) => `[${w.code}] ${w.message}`);
    }

    return extracted;
  }

  /** Split text into overlapping chunks. */
  chunk(text: string): Chunk[] {
    return chunkText(text, {
      maxTokens: this.config.maxChunkTokens ?? 500,
      overlapTokens: this.config.overlapTokens ?? 50,
    });
  }

  /** Embed a single text string. */
  async embed(text: string): Promise<EmbeddingVector> {
    return this.embedder.embed(text);
  }

  /** Embed multiple chunks and zip results into EmbeddedChunk[]. */
  async embedChunks(chunks: Chunk[]): Promise<EmbeddedChunk[]> {
    const vectors = await this.embedder.embedBatch(chunks.map((c) => c.content));
    return chunks.map((chunk, i) => ({
      ...chunk,
      embedding: vectors[i],
      model: 'snowflake-arctic-embed-s@384',
    }));
  }

  /** Search embeddings for the top-K most similar, returning their indices. */
  search(query: EmbeddingVector, embeddings: EmbeddingVector[], topK: number): number[] {
    const results = searchEmbeddings(query, embeddings, topK);
    return results.map((r) => r.index);
  }
}

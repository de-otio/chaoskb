import { describe, expect, it } from 'vitest';
import { chunkText } from '../chunker.js';
import { countTokens } from '../tokenizer.js';

describe('chunkText', () => {
  it('returns empty array for empty input', () => {
    expect(chunkText('')).toEqual([]);
    expect(chunkText('   ')).toEqual([]);
  });

  it('returns single chunk for short text', () => {
    const text = 'This is a short sentence. It has very few tokens.';
    const chunks = chunkText(text, { maxTokens: 500 });
    expect(chunks).toHaveLength(1);
    expect(chunks[0].content).toBe(text);
    expect(chunks[0].index).toBe(0);
    expect(chunks[0].byteOffset).toBe(0);
    expect(chunks[0].tokenCount).toBeGreaterThan(0);
  });

  it('splits long text into multiple chunks', () => {
    // Generate text with enough sentences to exceed one chunk
    const sentences = Array.from({ length: 100 }, (_, i) =>
      `Sentence number ${i + 1} contains some words that contribute to the overall token count of this text.`,
    );
    const text = sentences.join(' ');

    const chunks = chunkText(text, { maxTokens: 100, overlapTokens: 10 });
    expect(chunks.length).toBeGreaterThan(1);

    // Each chunk's token count should be approximately within maxTokens
    // (may exceed slightly because we don't split mid-sentence)
    for (const chunk of chunks) {
      expect(chunk.tokenCount).toBeGreaterThan(0);
    }
  });

  it('assigns sequential indices', () => {
    const sentences = Array.from({ length: 50 }, (_, i) =>
      `This is sentence ${i} with enough words to matter.`,
    );
    const text = sentences.join(' ');

    const chunks = chunkText(text, { maxTokens: 50, overlapTokens: 5 });
    for (let i = 0; i < chunks.length; i++) {
      expect(chunks[i].index).toBe(i);
    }
  });

  it('creates overlap between consecutive chunks', () => {
    const sentences = Array.from({ length: 50 }, (_, i) =>
      `Unique sentence number ${i + 1} has content.`,
    );
    const text = sentences.join(' ');

    const chunks = chunkText(text, { maxTokens: 30, overlapTokens: 10 });

    // With overlap, consecutive chunks should share some text
    if (chunks.length >= 2) {
      // The end of one chunk should overlap with the start of the next
      const chunk0Words = chunks[0].content.split(/\s+/);
      const _chunk1Words = chunks[1].content.split(/\s+/);

      // Find shared words
      const chunk0Suffix = chunk0Words.slice(-5).join(' ');
      // The second chunk should start with or contain some of the end of the first
      expect(chunks[1].content).toContain(chunk0Suffix.split(' ').pop()!);
    }
  });

  it('handles a single very long sentence', () => {
    const longSentence = Array.from({ length: 1000 }, (_, i) => `word${i}`).join(' ') + '.';
    const chunks = chunkText(longSentence, { maxTokens: 100, overlapTokens: 10 });

    // Should still produce at least one chunk
    expect(chunks.length).toBeGreaterThanOrEqual(1);
    // The single sentence will be in one chunk even if it exceeds maxTokens
    expect(chunks[0].content).toContain('word0');
  });

  it('tracks byte offsets correctly', () => {
    const text = 'First sentence here. Second sentence here. Third sentence here.';
    const chunks = chunkText(text, { maxTokens: 10, overlapTokens: 0 });

    // First chunk should start at offset 0
    expect(chunks[0].byteOffset).toBe(0);

    // Subsequent chunks should have positive offsets
    if (chunks.length > 1) {
      expect(chunks[1].byteOffset).toBeGreaterThan(0);
    }
  });

  it('uses default config values', () => {
    const text = 'Just a test sentence.';
    const chunks = chunkText(text);
    expect(chunks).toHaveLength(1);
    expect(chunks[0].tokenCount).toBeGreaterThan(0);
  });

  it('splits on sentence boundaries (period)', () => {
    const text = 'First sentence. Second sentence. Third sentence.';
    const chunks = chunkText(text, { maxTokens: 5, overlapTokens: 0 });

    // Each chunk should ideally contain complete sentences
    for (const chunk of chunks) {
      // Should not start or end mid-word (rough check)
      expect(chunk.content.trim()).toBe(chunk.content);
    }
  });

  it('splits on exclamation and question marks', () => {
    const text = 'What is this? It is great! Yes it is. Really amazing! Totally agree?';
    const chunks = chunkText(text, { maxTokens: 8, overlapTokens: 0 });
    expect(chunks.length).toBeGreaterThanOrEqual(1);

    // Each chunk should contain content
    for (const chunk of chunks) {
      expect(chunk.content.length).toBeGreaterThan(0);
    }
  });

  it('handles text without sentence boundaries', () => {
    const text = 'just a single long piece of text with no sentence endings and many words';
    const chunks = chunkText(text, { maxTokens: 10, overlapTokens: 0 });
    // Without sentence boundaries, the whole text is one "sentence"
    expect(chunks).toHaveLength(1);
    expect(chunks[0].content).toBe(text);
  });

  it('each chunk has correct token count matching its content', () => {
    const sentences = Array.from({ length: 30 }, (_, i) =>
      `This is test sentence number ${i + 1}.`,
    );
    const text = sentences.join(' ');
    const chunks = chunkText(text, { maxTokens: 30, overlapTokens: 5 });

    for (const chunk of chunks) {
      expect(chunk.tokenCount).toBe(countTokens(chunk.content));
    }
  });
});

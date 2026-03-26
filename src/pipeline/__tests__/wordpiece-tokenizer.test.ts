import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  clearVocabCache,
  CLS_ID,
  countWordPieceTokens,
  loadVocabulary,
  PAD_ID,
  SEP_ID,
  tokenize,
  UNK_ID,
} from '../wordpiece-tokenizer.js';

/** Path to the bundled BERT vocabulary. */
const VOCAB_PATH = join(__dirname, '..', 'vocab.txt');

afterEach(() => {
  clearVocabCache();
});

describe('loadVocabulary', () => {
  it('loads the BERT vocabulary file', () => {
    const vocab = loadVocabulary(VOCAB_PATH);
    expect(vocab.size).toBe(30522);
  });

  it('maps special tokens to correct IDs', () => {
    const vocab = loadVocabulary(VOCAB_PATH);
    expect(vocab.tokenToId.get('[PAD]')).toBe(PAD_ID);
    expect(vocab.tokenToId.get('[UNK]')).toBe(UNK_ID);
    expect(vocab.tokenToId.get('[CLS]')).toBe(CLS_ID);
    expect(vocab.tokenToId.get('[SEP]')).toBe(SEP_ID);
    expect(vocab.tokenToId.get('[MASK]')).toBe(103);
  });

  it('maps common English words', () => {
    const vocab = loadVocabulary(VOCAB_PATH);
    expect(vocab.tokenToId.has('the')).toBe(true);
    expect(vocab.tokenToId.has('of')).toBe(true);
    expect(vocab.tokenToId.has('and')).toBe(true);
  });

  it('maps continuation tokens with ## prefix', () => {
    const vocab = loadVocabulary(VOCAB_PATH);
    expect(vocab.tokenToId.has('##ing')).toBe(true);
    expect(vocab.tokenToId.has('##ed')).toBe(true);
    expect(vocab.tokenToId.has('##s')).toBe(true);
  });

  it('caches vocabulary on repeated loads', () => {
    const vocab1 = loadVocabulary(VOCAB_PATH);
    const vocab2 = loadVocabulary(VOCAB_PATH);
    expect(vocab1).toBe(vocab2); // Same reference
  });

  it('throws for nonexistent file', () => {
    expect(() => loadVocabulary('/nonexistent/vocab.txt')).toThrow();
  });
});

describe('tokenize', () => {
  it('wraps tokens with [CLS] and [SEP]', () => {
    const vocab = loadVocabulary(VOCAB_PATH);
    const ids = tokenize('hello', vocab);
    expect(ids[0]).toBe(BigInt(CLS_ID));
    expect(ids[ids.length - 1]).toBe(BigInt(SEP_ID));
  });

  it('produces at least 3 tokens for any non-empty input', () => {
    const vocab = loadVocabulary(VOCAB_PATH);
    const ids = tokenize('a', vocab);
    // [CLS] + at least one token + [SEP]
    expect(ids.length).toBeGreaterThanOrEqual(3);
  });

  it('tokenizes a simple sentence', () => {
    const vocab = loadVocabulary(VOCAB_PATH);
    const ids = tokenize('Hello world', vocab);
    // [CLS] hello world [SEP]
    expect(ids.length).toBeGreaterThanOrEqual(4);
    expect(ids[0]).toBe(BigInt(CLS_ID));
    expect(ids[ids.length - 1]).toBe(BigInt(SEP_ID));
    // All IDs should be valid (non-negative)
    for (const id of ids) {
      expect(id).toBeGreaterThanOrEqual(0n);
    }
  });

  it('lowercases input text', () => {
    const vocab = loadVocabulary(VOCAB_PATH);
    const lower = tokenize('hello world', vocab);
    const upper = tokenize('HELLO WORLD', vocab);
    expect(lower).toEqual(upper);
  });

  it('strips accents', () => {
    const vocab = loadVocabulary(VOCAB_PATH);
    const plain = tokenize('cafe', vocab);
    const accent = tokenize('café', vocab);
    expect(plain).toEqual(accent);
  });

  it('handles punctuation as separate tokens', () => {
    const vocab = loadVocabulary(VOCAB_PATH);
    const withPunct = tokenize('hello, world!', vocab);
    const withoutPunct = tokenize('hello world', vocab);
    // With punctuation should have more tokens (, and !)
    expect(withPunct.length).toBeGreaterThan(withoutPunct.length);
  });

  it('splits unknown words into subwords', () => {
    const vocab = loadVocabulary(VOCAB_PATH);
    // "embeddings" likely splits into "em" + "##bed" + "##ding" + "##s" or similar
    const ids = tokenize('embeddings', vocab);
    // Should have [CLS] + subword tokens + [SEP]
    expect(ids.length).toBeGreaterThanOrEqual(3);
    // Should not produce [UNK] for a real English word
    const unkId = BigInt(UNK_ID);
    const innerIds = ids.slice(1, -1); // Remove [CLS] and [SEP]
    expect(innerIds.some((id) => id === unkId)).toBe(false);
  });

  it('produces [UNK] for truly unknown characters', () => {
    const vocab = loadVocabulary(VOCAB_PATH);
    // A string of rare Unicode that won't be in BERT vocab
    const ids = tokenize('\u{1F4A9}', vocab); // 💩 emoji
    const innerIds = ids.slice(1, -1);
    // May produce UNK or empty inner (just CLS+SEP)
    if (innerIds.length > 0) {
      expect(innerIds.some((id) => id === BigInt(UNK_ID))).toBe(true);
    }
  });

  it('truncates to maxLength', () => {
    const vocab = loadVocabulary(VOCAB_PATH);
    const longText = 'word '.repeat(1000);
    const ids = tokenize(longText, vocab, 128);
    expect(ids.length).toBeLessThanOrEqual(128);
    expect(ids[0]).toBe(BigInt(CLS_ID));
    expect(ids[ids.length - 1]).toBe(BigInt(SEP_ID));
  });

  it('handles empty string', () => {
    const vocab = loadVocabulary(VOCAB_PATH);
    const ids = tokenize('', vocab);
    // Should be [CLS] [SEP]
    expect(ids).toEqual([BigInt(CLS_ID), BigInt(SEP_ID)]);
  });

  it('handles whitespace-only string', () => {
    const vocab = loadVocabulary(VOCAB_PATH);
    const ids = tokenize('   \t\n   ', vocab);
    expect(ids).toEqual([BigInt(CLS_ID), BigInt(SEP_ID)]);
  });

  it('returns consistent results for same input', () => {
    const vocab = loadVocabulary(VOCAB_PATH);
    const text = 'Quantum computing uses qubits for parallel computation.';
    const ids1 = tokenize(text, vocab);
    const ids2 = tokenize(text, vocab);
    expect(ids1).toEqual(ids2);
  });

  it('returns bigint IDs for ONNX int64 compatibility', () => {
    const vocab = loadVocabulary(VOCAB_PATH);
    const ids = tokenize('test', vocab);
    for (const id of ids) {
      expect(typeof id).toBe('bigint');
    }
  });
});

describe('countWordPieceTokens', () => {
  it('returns 0 for empty string', () => {
    const vocab = loadVocabulary(VOCAB_PATH);
    expect(countWordPieceTokens('', vocab)).toBe(0);
  });

  it('returns 0 for whitespace-only string', () => {
    const vocab = loadVocabulary(VOCAB_PATH);
    expect(countWordPieceTokens('   ', vocab)).toBe(0);
  });

  it('counts tokens for a simple sentence', () => {
    const vocab = loadVocabulary(VOCAB_PATH);
    // "hello world" → hello + world = 2 tokens
    const count = countWordPieceTokens('hello world', vocab);
    expect(count).toBe(2);
  });

  it('counts subword tokens correctly', () => {
    const vocab = loadVocabulary(VOCAB_PATH);
    // "electroencephalography" is not in BERT vocab — it must split into subwords
    const count = countWordPieceTokens('electroencephalography', vocab);
    expect(count).toBeGreaterThan(1);
  });

  it('does not count [CLS] and [SEP]', () => {
    const vocab = loadVocabulary(VOCAB_PATH);
    const count = countWordPieceTokens('hello', vocab);
    const ids = tokenize('hello', vocab);
    // tokenize includes CLS+SEP, countWordPieceTokens does not
    expect(ids.length).toBe(count + 2);
  });

  it('handles punctuation', () => {
    const vocab = loadVocabulary(VOCAB_PATH);
    const withPunct = countWordPieceTokens('hello, world!', vocab);
    const withoutPunct = countWordPieceTokens('hello world', vocab);
    // Punctuation adds tokens
    expect(withPunct).toBeGreaterThan(withoutPunct);
  });

  it('scales with text length', () => {
    const vocab = loadVocabulary(VOCAB_PATH);
    const short = countWordPieceTokens('hello world', vocab);
    const long = countWordPieceTokens(
      'hello world this is a much longer sentence with many more words',
      vocab,
    );
    expect(long).toBeGreaterThan(short);
  });
});

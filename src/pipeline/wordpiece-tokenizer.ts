/**
 * BERT-compatible WordPiece tokenizer for snowflake-arctic-embed-s.
 *
 * Implements the standard BERT tokenization pipeline:
 *   1. Lowercase + strip accents
 *   2. Basic tokenization (whitespace + punctuation splitting)
 *   3. WordPiece subword segmentation using the model vocabulary
 *
 * The vocabulary is loaded from a vocab.txt file where each line is a
 * token and the line number (0-based) is its ID.
 */

import { readFileSync } from 'node:fs';

/** Special token IDs matching the BERT vocabulary layout. */
const PAD_ID = 0;
const UNK_ID = 100;
const CLS_ID = 101;
const SEP_ID = 102;

/** Maximum subword length to attempt during WordPiece lookup. */
const MAX_WORD_LENGTH = 200;

/** WordPiece continuation prefix. */
const CONTINUATION_PREFIX = '##';

/**
 * A loaded vocabulary mapping tokens to their integer IDs.
 */
export interface Vocabulary {
  tokenToId: Map<string, number>;
  size: number;
}

/** Singleton cache: vocab path → loaded vocabulary. */
const vocabCache = new Map<string, Vocabulary>();

/**
 * Load a BERT vocab.txt file into a token-to-ID map.
 * Results are cached by path for the lifetime of the process.
 *
 * @param vocabPath - Absolute path to vocab.txt.
 * @returns The loaded vocabulary.
 */
export function loadVocabulary(vocabPath: string): Vocabulary {
  const cached = vocabCache.get(vocabPath);
  if (cached) {
    return cached;
  }

  const content = readFileSync(vocabPath, 'utf-8');
  const lines = content.split(/\r?\n/);
  const tokenToId = new Map<string, number>();

  for (let i = 0; i < lines.length; i++) {
    const token = lines[i];
    if (token.length > 0) {
      tokenToId.set(token, i);
    }
  }

  const vocab: Vocabulary = { tokenToId, size: tokenToId.size };
  vocabCache.set(vocabPath, vocab);
  return vocab;
}

/**
 * Clear the vocabulary cache (useful for testing).
 */
export function clearVocabCache(): void {
  vocabCache.clear();
}

/**
 * Tokenize text into BERT token IDs using WordPiece.
 *
 * Produces a sequence: [CLS] tokens... [SEP], truncated to maxLength.
 *
 * @param text - Input text string.
 * @param vocab - Loaded vocabulary.
 * @param maxLength - Maximum sequence length including special tokens (default: 512).
 * @returns Array of token IDs as bigint (for ONNX int64 tensors).
 */
export function tokenize(
  text: string,
  vocab: Vocabulary,
  maxLength: number = 512,
): bigint[] {
  const tokens = basicTokenize(text);
  const ids: bigint[] = [BigInt(CLS_ID)];

  // Reserve space for [SEP]
  const maxTokenSlots = maxLength - 2;

  for (const token of tokens) {
    if (ids.length - 1 >= maxTokenSlots) {
      break;
    }

    const subwordIds = wordpieceTokenize(token, vocab);
    for (const id of subwordIds) {
      if (ids.length - 1 >= maxTokenSlots) {
        break;
      }
      ids.push(BigInt(id));
    }
  }

  ids.push(BigInt(SEP_ID));
  return ids;
}

/**
 * Count the number of WordPiece tokens a text would produce.
 * Does not include [CLS] and [SEP] special tokens.
 *
 * @param text - Input text string.
 * @param vocab - Loaded vocabulary.
 * @returns Number of WordPiece tokens.
 */
export function countWordPieceTokens(text: string, vocab: Vocabulary): number {
  const tokens = basicTokenize(text);
  let count = 0;

  for (const token of tokens) {
    count += wordpieceTokenize(token, vocab).length;
  }

  return count;
}

/**
 * BERT basic tokenization: lowercase, strip accents, split on whitespace
 * and punctuation.
 *
 * @param text - Raw input text.
 * @returns Array of lowercase word tokens.
 */
function basicTokenize(text: string): string[] {
  // Lowercase
  let normalized = text.toLowerCase();

  // Strip accents (NFD decomposition, remove combining marks)
  normalized = normalized.normalize('NFD').replace(/[\u0300-\u036f]/g, '');

  // Clean: replace control characters and zero-width chars with space
  normalized = normalized.replace(/[\x00-\x1f\x7f-\x9f\u200b-\u200f\ufeff]/g, ' ');

  // Tokenize CJK characters: add spaces around each CJK character
  // so they become individual tokens
  normalized = tokenizeCjk(normalized);

  // Split on whitespace, then split each word on punctuation boundaries
  const words = normalized.split(/\s+/).filter((w) => w.length > 0);
  const tokens: string[] = [];

  for (const word of words) {
    tokens.push(...splitOnPunctuation(word));
  }

  return tokens;
}

/**
 * Split a word on punctuation characters. Punctuation becomes its own token.
 *
 * @param word - A whitespace-delimited word.
 * @returns Array of sub-tokens.
 */
function splitOnPunctuation(word: string): string[] {
  const tokens: string[] = [];
  let current = '';

  for (const char of word) {
    if (isPunctuation(char)) {
      if (current.length > 0) {
        tokens.push(current);
        current = '';
      }
      tokens.push(char);
    } else {
      current += char;
    }
  }

  if (current.length > 0) {
    tokens.push(current);
  }

  return tokens;
}

/**
 * Check if a character is punctuation (Unicode general categories P*
 * plus ASCII symbols).
 */
function isPunctuation(char: string): boolean {
  const code = char.codePointAt(0)!;

  // ASCII punctuation ranges
  if (
    (code >= 33 && code <= 47) ||   // ! " # $ % & ' ( ) * + , - . /
    (code >= 58 && code <= 64) ||   // : ; < = > ? @
    (code >= 91 && code <= 96) ||   // [ \ ] ^ _ `
    (code >= 123 && code <= 126)    // { | } ~
  ) {
    return true;
  }

  // Unicode punctuation (general category P)
  // This is a simplified check covering the most common ranges
  if (
    (code >= 0x2000 && code <= 0x206f) || // General punctuation
    (code >= 0x3000 && code <= 0x303f) || // CJK symbols and punctuation
    (code >= 0xfe30 && code <= 0xfe6f) || // CJK compatibility forms
    (code >= 0xff00 && code <= 0xff0f) || // Fullwidth punctuation
    (code >= 0xff1a && code <= 0xff20) ||
    (code >= 0xff3b && code <= 0xff40) ||
    (code >= 0xff5b && code <= 0xff65)
  ) {
    return true;
  }

  return false;
}

/**
 * Add spaces around CJK characters so they tokenize as individual tokens.
 */
function tokenizeCjk(text: string): string {
  const output: string[] = [];

  for (const char of text) {
    const cp = char.codePointAt(0)!;
    if (isCjkCharacter(cp)) {
      output.push(' ', char, ' ');
    } else {
      output.push(char);
    }
  }

  return output.join('');
}

/**
 * Check if a code point is a CJK character.
 */
function isCjkCharacter(cp: number): boolean {
  return (
    (cp >= 0x4e00 && cp <= 0x9fff) ||
    (cp >= 0x3400 && cp <= 0x4dbf) ||
    (cp >= 0x20000 && cp <= 0x2a6df) ||
    (cp >= 0x2a700 && cp <= 0x2b73f) ||
    (cp >= 0x2b740 && cp <= 0x2b81f) ||
    (cp >= 0x2b820 && cp <= 0x2ceaf) ||
    (cp >= 0xf900 && cp <= 0xfaff) ||
    (cp >= 0x2f800 && cp <= 0x2fa1f)
  );
}

/**
 * WordPiece subword tokenization for a single pre-tokenized word.
 *
 * Greedily matches the longest prefix in the vocabulary, then continues
 * with ## continuation tokens for the remainder.
 *
 * @param word - A single pre-tokenized word (lowercase, no whitespace).
 * @param vocab - Loaded vocabulary.
 * @returns Array of integer token IDs.
 */
function wordpieceTokenize(word: string, vocab: Vocabulary): number[] {
  if (word.length > MAX_WORD_LENGTH) {
    return [UNK_ID];
  }

  const ids: number[] = [];
  let start = 0;

  while (start < word.length) {
    let end = word.length;
    let foundId: number | undefined;

    while (start < end) {
      const substr = start === 0
        ? word.slice(start, end)
        : CONTINUATION_PREFIX + word.slice(start, end);

      const id = vocab.tokenToId.get(substr);
      if (id !== undefined) {
        foundId = id;
        break;
      }
      end--;
    }

    if (foundId === undefined) {
      // Character not in vocabulary at all — entire word is [UNK]
      return [UNK_ID];
    }

    ids.push(foundId);
    start = end;
  }

  return ids;
}

/**
 * Exports for use by the embedder and token counter.
 */
export {
  PAD_ID,
  UNK_ID,
  CLS_ID,
  SEP_ID,
};

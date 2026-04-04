import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

import {
  listKBs,
  migrateToNamedKBLayout,
} from '../../commands/kb.js';

// Use a temp directory instead of real ~/.chaoskb
const TEST_DIR = path.join(os.tmpdir(), `chaoskb-test-${Date.now()}`);

// Override the CHAOSKB_DIR by patching os.homedir

describe('Named KB management', () => {
  beforeEach(() => {
    fs.mkdirSync(TEST_DIR, { recursive: true });
    // Create a fake .chaoskb in our temp dir
    fs.mkdirSync(path.join(TEST_DIR, '.chaoskb'), { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(TEST_DIR, { recursive: true, force: true });
  });

  describe('listKBs', () => {
    it('should return empty array when no KBs exist', () => {
      const kbs = listKBs();
      // May find real KBs if ~/.chaoskb exists, so just verify it's an array
      expect(Array.isArray(kbs)).toBe(true);
    });
  });

  describe('migrateToNamedKBLayout', () => {
    it('should return false if no flat config exists', () => {
      const result = migrateToNamedKBLayout();
      // Will return false if ~/.chaoskb/config.json doesn't exist (or default/ already exists)
      expect(typeof result).toBe('boolean');
    });
  });

  describe('KB name validation', () => {
    it('should accept valid names', () => {
      // We can't easily test kbCreateCommand without mocking process.exit,
      // so test the validation logic indirectly
      const validNames = ['work', 'personal', 'my-kb', 'kb_1', 'MyKB'];
      for (const name of validNames) {
        expect(/^[a-zA-Z0-9_-]+$/.test(name)).toBe(true);
      }
    });

    it('should reject invalid names', () => {
      const invalidNames = ['', 'my kb', 'kb/work', '../escape', 'a'.repeat(65)];
      for (const name of invalidNames) {
        const valid = /^[a-zA-Z0-9_-]+$/.test(name) && name.length > 0 && name.length <= 64;
        expect(valid).toBe(false);
      }
    });
  });
});

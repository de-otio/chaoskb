import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { SequenceCounter } from '../sequence.js';

describe('SequenceCounter', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'chaoskb-seq-'));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('starts at 1 on first call', () => {
    const counter = new SequenceCounter(join(tmpDir, 'sequence'));
    expect(counter.next()).toBe(1);
  });

  it('increments monotonically', () => {
    const counter = new SequenceCounter(join(tmpDir, 'sequence'));
    expect(counter.next()).toBe(1);
    expect(counter.next()).toBe(2);
    expect(counter.next()).toBe(3);
  });

  it('persists across instances', () => {
    const filePath = join(tmpDir, 'sequence');
    const counter1 = new SequenceCounter(filePath);
    counter1.next(); // 1
    counter1.next(); // 2

    const counter2 = new SequenceCounter(filePath);
    expect(counter2.next()).toBe(3);
  });

  it('peek returns current without incrementing', () => {
    const counter = new SequenceCounter(join(tmpDir, 'sequence'));
    expect(counter.peek()).toBe(0);
    counter.next();
    expect(counter.peek()).toBe(1);
  });

  it('handles missing file gracefully', () => {
    const counter = new SequenceCounter(join(tmpDir, 'nonexistent', 'sequence'));
    expect(counter.next()).toBe(1);
  });
});

describe('SSHSigner.buildCanonical with sequence', () => {
  it('includes sequence in canonical string', async () => {
    // Import dynamically to avoid needing a real SSH key
    const { SSHSigner } = await import('../ssh-signer.js');
    const signer = new SSHSigner('/nonexistent/key');

    const canonical = signer.buildCanonical(
      'PUT',
      '/blobs/b_123',
      '2026-03-30T14:30:00.000Z',
      42,
      'abc123',
    );

    expect(canonical).toBe(
      'chaoskb-auth\nPUT /blobs/b_123\n2026-03-30T14:30:00.000Z\n42\nabc123',
    );
  });

  it('different sequence produces different canonical', async () => {
    const { SSHSigner } = await import('../ssh-signer.js');
    const signer = new SSHSigner('/nonexistent/key');

    const c1 = signer.buildCanonical('GET', '/blobs', '2026-03-30T14:30:00.000Z', 1, '');
    const c2 = signer.buildCanonical('GET', '/blobs', '2026-03-30T14:30:00.000Z', 2, '');

    expect(c1).not.toBe(c2);
  });
});

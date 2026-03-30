/**
 * Tests for the auto-bootstrap lock module.
 *
 * Uses temporary directories to verify locking behavior
 * without touching the real ~/.chaoskb/.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { acquireBootstrapLock } from '../bootstrap-lock.js';

describe('bootstrap-lock', () => {
  let tmpDir: string;
  let chaoskbDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chaoskb-test-'));
    chaoskbDir = path.join(tmpDir, '.chaoskb');
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should acquire and release a lock', async () => {
    fs.mkdirSync(chaoskbDir, { recursive: true });

    const release = await acquireBootstrapLock(chaoskbDir);
    const lockPath = path.join(chaoskbDir, '.bootstrap.lock');
    expect(fs.existsSync(lockPath)).toBe(true);

    release();
    expect(fs.existsSync(lockPath)).toBe(false);
  });

  it('should create .chaoskb directory if it does not exist', async () => {
    expect(fs.existsSync(chaoskbDir)).toBe(false);

    const release = await acquireBootstrapLock(chaoskbDir);
    expect(fs.existsSync(chaoskbDir)).toBe(true);

    release();
  });

  it('should remove stale locks', async () => {
    fs.mkdirSync(chaoskbDir, { recursive: true });
    const lockPath = path.join(chaoskbDir, '.bootstrap.lock');

    // Create a stale lock (set mtime to 60 seconds ago)
    fs.writeFileSync(lockPath, JSON.stringify({ pid: 99999, timestamp: Date.now() - 60000 }));
    const pastTime = new Date(Date.now() - 60000);
    fs.utimesSync(lockPath, pastTime, pastTime);

    const release = await acquireBootstrapLock(chaoskbDir);
    expect(fs.existsSync(lockPath)).toBe(true);

    release();
  });

  it('should write pid and timestamp to lock file', async () => {
    fs.mkdirSync(chaoskbDir, { recursive: true });

    const release = await acquireBootstrapLock(chaoskbDir);
    const lockPath = path.join(chaoskbDir, '.bootstrap.lock');
    const content = JSON.parse(fs.readFileSync(lockPath, 'utf-8'));

    expect(content.pid).toBe(process.pid);
    expect(typeof content.timestamp).toBe('number');
    expect(content.timestamp).toBeLessThanOrEqual(Date.now());

    release();
  });

  it('should handle lock released between retries', async () => {
    fs.mkdirSync(chaoskbDir, { recursive: true });
    const lockPath = path.join(chaoskbDir, '.bootstrap.lock');

    // Create a lock that will be removed shortly
    fs.writeFileSync(lockPath, JSON.stringify({ pid: process.pid, timestamp: Date.now() }));

    // Remove it after 200ms (before the first retry at 500ms would give up)
    setTimeout(() => {
      try { fs.unlinkSync(lockPath); } catch { /* ignore */ }
    }, 200);

    const release = await acquireBootstrapLock(chaoskbDir);
    expect(fs.existsSync(lockPath)).toBe(true);

    release();
  });
});

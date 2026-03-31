import { readFileSync, writeFileSync, mkdirSync, renameSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';

/**
 * Per-device monotonic sequence counter for replay protection.
 *
 * Each signed request includes a sequence number that the server tracks.
 * The server rejects any request with a sequence <= the highest it has seen,
 * preventing replay attacks.
 *
 * The counter is persisted to disk so it survives process restarts.
 */
export class SequenceCounter {
  private readonly filePath: string;
  private current: number;

  constructor(filePath?: string) {
    this.filePath = filePath ?? join(homedir(), '.chaoskb', 'sequence');
    this.current = this.load();
  }

  /** Get the next sequence number (monotonically increasing). */
  next(): number {
    this.current += 1;
    this.persist();
    return this.current;
  }

  /** Get the current sequence number without incrementing. */
  peek(): number {
    return this.current;
  }

  private load(): number {
    try {
      const content = readFileSync(this.filePath, 'utf-8').trim();
      const value = parseInt(content, 10);
      return isNaN(value) ? 0 : value;
    } catch {
      return 0;
    }
  }

  private persist(): void {
    const dir = dirname(this.filePath);
    mkdirSync(dir, { recursive: true, mode: 0o700 });

    // Atomic write: write to temp file, then rename
    const tmpPath = this.filePath + '.tmp';
    writeFileSync(tmpPath, String(this.current), { mode: 0o600 });
    renameSync(tmpPath, this.filePath);
  }
}

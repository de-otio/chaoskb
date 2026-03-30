import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

const STALE_THRESHOLD_MS = 30_000;
const RETRY_INTERVAL_MS = 500;
const MAX_RETRIES = 60;

function getChaoskbDir(baseDir?: string): string {
  return baseDir ?? path.join(os.homedir(), '.chaoskb');
}

/**
 * Acquire an exclusive file lock for bootstrap.
 * Uses O_CREAT | O_EXCL for atomic creation.
 * Returns a release function.
 */
export async function acquireBootstrapLock(baseDir?: string): Promise<() => void> {
  const chaoskbDir = getChaoskbDir(baseDir);
  const lockPath = path.join(chaoskbDir, '.bootstrap.lock');

  // Ensure the directory exists before trying to create the lock file
  if (!fs.existsSync(chaoskbDir)) {
    fs.mkdirSync(chaoskbDir, { recursive: true, mode: 0o700 });
  }

  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    try {
      const fd = fs.openSync(lockPath, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY);
      // Write PID and timestamp for stale lock detection
      fs.writeSync(fd, JSON.stringify({ pid: process.pid, timestamp: Date.now() }));
      fs.closeSync(fd);

      return () => {
        try {
          fs.unlinkSync(lockPath);
        } catch {
          // Lock file may have already been removed
        }
      };
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') {
        throw err;
      }

      // Lock file exists — check if it's stale
      try {
        const stat = fs.statSync(lockPath);
        const ageMs = Date.now() - stat.mtimeMs;
        if (ageMs > STALE_THRESHOLD_MS) {
          // Stale lock — remove and retry
          fs.unlinkSync(lockPath);
          continue;
        }
      } catch {
        // Lock file disappeared between checks — retry
        continue;
      }

      // Lock is held and not stale — wait and retry
      await new Promise((resolve) => setTimeout(resolve, RETRY_INTERVAL_MS));
    }
  }

  throw new Error(
    'Timed out waiting for bootstrap lock. If ChaosKB is not running elsewhere, ' +
    `delete ${lockPath} and try again.`,
  );
}

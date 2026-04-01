import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

export interface GitHubDetectionResult {
  username: string | null;
  accounts: string[];
}

export interface GitHubKeyMatch {
  localKeyPath: string;
  localKeyFingerprint: string;
  githubKeyLine: string;
}

/**
 * E1: Detect GitHub username via `gh auth status`.
 *
 * Parses the output to find the authenticated username. Supports multi-account
 * GitHub CLI configurations. Returns null if gh is not installed or not authenticated.
 */
export async function detectGitHubUsername(): Promise<GitHubDetectionResult> {
  try {
    const output = await execCommand('gh', ['auth', 'status']);
    return parseGhAuthStatus(output);
  } catch {
    // gh not installed, not authenticated, or command failed
    return { username: null, accounts: [] };
  }
}

/**
 * Parse `gh auth status` output to extract username(s).
 *
 * Example output:
 *   github.com
 *     ✓ Logged in to github.com account rmyers (keyring)
 *     - Active account: true
 */
export function parseGhAuthStatus(output: string): GitHubDetectionResult {
  const accounts: string[] = [];
  // Match patterns like "Logged in to github.com account <username>"
  // or "Logged in to github.com as <username>"
  const patterns = [
    /Logged in to github\.com account (\S+)/g,
    /Logged in to github\.com as (\S+)/g,
  ];

  for (const pattern of patterns) {
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(output)) !== null) {
      const username = match[1].replace(/[()]/g, '');
      if (!accounts.includes(username)) {
        accounts.push(username);
      }
    }
  }

  return {
    username: accounts.length > 0 ? accounts[0] : null,
    accounts,
  };
}

/**
 * E2: Fetch GitHub SSH keys for a username and match against local keys.
 *
 * Fetches https://github.com/<username>.keys (one public key per line)
 * and compares against SSH public keys in ~/.ssh/.
 */
export async function matchGitHubKeys(username: string): Promise<GitHubKeyMatch[]> {
  const githubKeys = await fetchGitHubKeys(username);
  if (githubKeys.length === 0) return [];

  const localKeys = listLocalSSHKeys();
  const matches: GitHubKeyMatch[] = [];

  for (const local of localKeys) {
    for (const ghKey of githubKeys) {
      // Compare by key content (type + base64 blob), ignoring comments
      if (keysMatch(local.content, ghKey)) {
        matches.push({
          localKeyPath: local.path,
          localKeyFingerprint: local.fingerprint,
          githubKeyLine: ghKey,
        });
      }
    }
  }

  return matches;
}

/**
 * Fetch SSH public keys from GitHub for a user.
 * Returns one key per line, or empty array on error.
 */
export async function fetchGitHubKeys(username: string): Promise<string[]> {
  try {
    const response = await fetch(`https://github.com/${encodeURIComponent(username)}.keys`, {
      signal: AbortSignal.timeout(10_000),
    });

    if (!response.ok) {
      return [];
    }

    const text = await response.text();
    return text
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
  } catch {
    return [];
  }
}

interface LocalKey {
  path: string;
  content: string;
  fingerprint: string;
}

/**
 * List SSH public keys in ~/.ssh/.
 */
function listLocalSSHKeys(): LocalKey[] {
  const sshDir = path.join(os.homedir(), '.ssh');
  const keys: LocalKey[] = [];

  try {
    const files = fs.readdirSync(sshDir);
    for (const file of files) {
      if (!file.endsWith('.pub')) continue;
      const filePath = path.join(sshDir, file);
      try {
        const content = fs.readFileSync(filePath, 'utf-8').trim();
        const parts = content.split(/\s+/);
        if (parts.length >= 2 && (parts[0].startsWith('ssh-') || parts[0].startsWith('ecdsa-'))) {
          const blob = Buffer.from(parts[1], 'base64');
          const hash = createHash('sha256').update(blob).digest('base64').replace(/=+$/, '');
          keys.push({
            path: filePath,
            content,
            fingerprint: `SHA256:${hash}`,
          });
        }
      } catch {
        // Skip unreadable files
      }
    }
  } catch {
    // ~/.ssh doesn't exist or isn't readable
  }

  return keys;
}

/**
 * Compare two SSH public keys by their type and base64 blob.
 * Ignores comments (the third field).
 */
function keysMatch(localContent: string, githubLine: string): boolean {
  const localParts = localContent.split(/\s+/);
  const ghParts = githubLine.split(/\s+/);

  if (localParts.length < 2 || ghParts.length < 2) return false;

  // Compare key type and base64 blob
  return localParts[0] === ghParts[0] && localParts[1] === ghParts[1];
}

function execCommand(command: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(command, args, { timeout: 10_000 }, (error, stdout, stderr) => {
      if (error) {
        reject(error);
        return;
      }
      // gh auth status outputs to stderr
      resolve(stdout + stderr);
    });
  });
}

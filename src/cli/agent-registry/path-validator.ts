import * as os from 'node:os';
import * as path from 'node:path';

/**
 * Allowlisted directory prefixes for agent config files.
 * These are the only locations where ChaosKB will read/write agent configs.
 */
const ALLOWED_PREFIXES = [
  '~/.config/',
  '~/.cursor/',
  '~/Library/Application Support/',
  '~/.claude.json',
  '~/.continue/',
  '~/.codeium/',
  '~/.vscode/',
];

/**
 * Allowlisted relative paths for project-level config.
 */
const ALLOWED_RELATIVE_PREFIXES = [
  '.vscode/',
  '.cursor/',
];

function expandHome(p: string): string {
  if (p.startsWith('~/') || p === '~') {
    return path.join(os.homedir(), p.slice(1));
  }
  return p;
}

/**
 * Validate that a config file path is within the allowed directories.
 * Throws an error if the path is not allowed.
 *
 * Rules:
 * - Reject any path containing '..' (directory traversal)
 * - Reject absolute paths not in the allowlist
 * - Allow relative paths only if they match project config patterns
 */
export function validateConfigPath(configFilePath: string): void {
  // Reject directory traversal
  if (configFilePath.includes('..')) {
    throw new Error(
      `Rejected config path with directory traversal: ${configFilePath}`,
    );
  }

  // Resolve the path to an absolute path for comparison
  const resolved = path.resolve(configFilePath);
  const _home = os.homedir();

  // Check if it's a relative project config path
  if (!path.isAbsolute(configFilePath)) {
    const isAllowedRelative = ALLOWED_RELATIVE_PREFIXES.some((prefix) =>
      configFilePath.startsWith(prefix),
    );
    if (isAllowedRelative) {
      return;
    }
    throw new Error(
      `Rejected relative config path not in allowlist: ${configFilePath}`,
    );
  }

  // For absolute paths, check against the allowlist
  const isAllowed = ALLOWED_PREFIXES.some((prefix) => {
    const expandedPrefix = expandHome(prefix);

    // Handle exact file matches (e.g., ~/.claude.json)
    if (!prefix.endsWith('/')) {
      return resolved === expandedPrefix;
    }

    // Handle directory prefix matches
    return resolved.startsWith(expandedPrefix);
  });

  if (!isAllowed) {
    throw new Error(
      `Rejected config path outside allowlist: ${configFilePath}. ` +
      `Path must be within one of: ${ALLOWED_PREFIXES.join(', ')}`,
    );
  }
}

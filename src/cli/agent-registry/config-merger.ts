import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateConfigPath } from './path-validator.js';

// Resolve the MCP server script path relative to this file at build time.
// config-merger lives at dist/cli/agent-registry/, MCP entry is at dist/cli/index.js
export const MCP_SCRIPT_PATH = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'index.js',
);

interface McpServerEntry {
  command: string;
  args: string[];
  env?: Record<string, string>;
}

interface McpConfig {
  mcpServers?: Record<string, McpServerEntry>;
  [key: string]: unknown;
}

/**
 * Read and parse an agent's MCP config file.
 * Returns the parsed config, or a new empty config if the file doesn't exist or is malformed.
 */
function readConfig(configFilePath: string): { config: McpConfig; wasCreated: boolean } {
  try {
    const raw = fs.readFileSync(configFilePath, 'utf-8');
    const config = JSON.parse(raw) as McpConfig;
    if (typeof config !== 'object' || config === null || Array.isArray(config)) {
      console.warn(`  Warning: ${configFilePath} contains invalid config, creating new.`);
      return { config: {}, wasCreated: true };
    }
    return { config, wasCreated: false };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return { config: {}, wasCreated: true };
    }
    // Malformed JSON
    console.warn(`  Warning: ${configFilePath} has malformed JSON, creating new.`);
    return { config: {}, wasCreated: true };
  }
}

/**
 * Write config back to file, preserving pretty formatting.
 */
function writeConfig(configFilePath: string, config: McpConfig): void {
  const dir = path.dirname(configFilePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(configFilePath, JSON.stringify(config, null, 2) + '\n', {
    mode: 0o600,
  });
}

export interface ConfigPreview {
  configFilePath: string;
  before: McpServerEntry | undefined;
  after: McpServerEntry;
  isNew: boolean;
}

/**
 * Preview what mergeAgentConfig would write, without actually writing anything.
 */
export function previewAgentConfig(configFilePath: string, args: string[] = []): ConfigPreview {
  const { config } = readConfig(configFilePath);
  const before = config.mcpServers?.chaoskb;
  const after: McpServerEntry = {
    command: process.execPath,
    args: [MCP_SCRIPT_PATH, ...args],
  };
  return { configFilePath, before, after, isNew: before === undefined };
}

/**
 * Add or update the ChaosKB MCP server entry in an agent's config file.
 * Preserves all other entries in the config.
 */
export async function mergeAgentConfig(
  configFilePath: string,
  args: string[] = [],
): Promise<void> {
  // Validate the config path is within allowed directories
  validateConfigPath(configFilePath);

  const { config } = readConfig(configFilePath);

  // Ensure mcpServers exists
  if (!config.mcpServers) {
    config.mcpServers = {};
  }

  // Add/update chaoskb entry.
  // Use the absolute node binary path + script path to avoid picking up the wrong
  // Node.js version from PATH (e.g. Claude Desktop may inject old NVM paths first).
  config.mcpServers.chaoskb = {
    command: process.execPath,
    args: [MCP_SCRIPT_PATH, ...args],
  };

  writeConfig(configFilePath, config);
}

/**
 * Find the nearest git workspace root from a starting directory.
 */
function findWorkspaceRoot(startDir: string): string | null {
  let dir = startDir;
  while (dir !== path.dirname(dir)) {
    if (fs.existsSync(path.join(dir, '.git'))) {
      return dir;
    }
    dir = path.dirname(dir);
  }
  return null;
}

/**
 * Register ChaosKB in the workspace .mcp.json file.
 * Used by the VS Code extension which reads MCP servers from .mcp.json,
 * not from ~/.claude/settings.json.
 *
 * Uses the short `chaoskb-mcp` command (not absolute paths) since
 * .mcp.json is often checked into git and shared across machines.
 */
export function registerInWorkspaceMcpJson(workspaceRoot: string): boolean {
  const mcpJsonPath = path.join(workspaceRoot, '.mcp.json');

  // Read existing .mcp.json or create new
  let config: McpConfig;
  try {
    const raw = fs.readFileSync(mcpJsonPath, 'utf-8');
    config = JSON.parse(raw) as McpConfig;
  } catch {
    config = {};
  }

  if (!config.mcpServers) {
    config.mcpServers = {};
  }

  // Already registered
  if (config.mcpServers.chaoskb) {
    return false;
  }

  // Use short command name — .mcp.json may be shared across machines
  config.mcpServers.chaoskb = {
    command: 'chaoskb-mcp',
    args: [],
  };

  fs.writeFileSync(mcpJsonPath, JSON.stringify(config, null, 2) + '\n');
  return true;
}

/**
 * Auto-detect VS Code workspace and register in .mcp.json if applicable.
 * Returns the workspace root if registration succeeded, null otherwise.
 */
export function autoRegisterVSCodeWorkspace(): string | null {
  // Only run when inside VS Code
  if (!process.env['VSCODE_CLI'] && !process.env['VSCODE_PID']) {
    return null;
  }

  // INIT_CWD is the directory where `npm install` was invoked (set by npm).
  // process.cwd() during postinstall points to the package install dir, not the user's workspace.
  const startDir = process.env['INIT_CWD'] || process.cwd();
  const workspaceRoot = findWorkspaceRoot(startDir);
  if (!workspaceRoot) return null;

  try {
    const added = registerInWorkspaceMcpJson(workspaceRoot);
    return added ? workspaceRoot : null;
  } catch {
    return null;
  }
}

/**
 * Remove the ChaosKB MCP server entry from an agent's config file.
 * Preserves all other entries.
 */
export async function removeAgentConfig(configFilePath: string): Promise<void> {
  validateConfigPath(configFilePath);

  const { config } = readConfig(configFilePath);

  if (config.mcpServers && 'chaoskb' in config.mcpServers) {
    delete config.mcpServers.chaoskb;

    // If mcpServers is now empty, keep the key but as empty object
    // so the config file format remains valid for the agent
    writeConfig(configFilePath, config);
  }
}

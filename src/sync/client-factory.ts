import { homedir } from 'node:os';
import { join } from 'node:path';
import type { SyncConfig } from './types.js';
import type { ISyncSequenceRepository } from '../storage/types.js';
import { SSHSigner } from './ssh-signer.js';
import { SyncHttpClient } from './http-client.js';

/**
 * Create a SyncHttpClient from explicit config.
 *
 * Requires a DB-backed ISyncSequenceRepository to prevent
 * sequence counter drift between SQLite and legacy flat files.
 */
export function createSyncHttpClientFromConfig(
  config: SyncConfig,
  sequence: ISyncSequenceRepository,
): SyncHttpClient {
  const signer = new SSHSigner(config.sshKeyPath);
  return new SyncHttpClient(config, signer, sequence);
}

/**
 * Create a SyncHttpClient by loading config from disk.
 *
 * Opens the personal database to use the SQLite-backed sequence counter,
 * ensuring all code paths share the same counter and avoiding drift.
 */
export async function createSyncHttpClient(): Promise<{
  client: SyncHttpClient;
  config: SyncConfig;
}> {
  const { loadConfig } = await import('../cli/commands/setup.js');
  const config = await loadConfig();

  if (!config?.endpoint) {
    throw new Error('Sync is not configured. Run `chaoskb-mcp setup-sync` first.');
  }

  const endpoint = config.endpoint;
  const sshKeyPath = config.sshKeyPath ?? join(homedir(), '.ssh', 'id_ed25519');
  const syncConfig: SyncConfig = { endpoint, sshKeyPath };

  const { DatabaseManager } = await import('../storage/database-manager.js');
  const dbManager = new DatabaseManager();
  const db = dbManager.getPersonalDb();

  const client = createSyncHttpClientFromConfig(syncConfig, db.syncSequence);
  return { client, config: syncConfig };
}

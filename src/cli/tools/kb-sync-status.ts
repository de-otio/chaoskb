import * as fs from 'node:fs';
import * as path from 'node:path';
import type { ChaosKBConfig } from '../mcp-server.js';
import { CHAOSKB_DIR } from '../bootstrap.js';

/**
 * MCP tool: kb_sync_status
 *
 * Returns the current sync status, key type, and device configuration.
 */
export async function kbSyncStatus(): Promise<string> {
  const configPath = path.join(CHAOSKB_DIR, 'config.json');

  if (!fs.existsSync(configPath)) {
    return JSON.stringify({
      status: 'not_configured',
      message: 'ChaosKB is not configured. Run any KB tool to auto-bootstrap.',
    });
  }

  const config = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as ChaosKBConfig;

  const result: Record<string, unknown> = {
    status: config.syncEnabled ? 'active' : config.syncPending ? 'pending' : 'disabled',
    securityTier: config.securityTier,
    syncEnabled: config.syncEnabled ?? false,
  };

  if (config.endpoint) {
    result.endpoint = config.endpoint;
  }

  if (config.sshKeyFingerprint) {
    result.sshKeyFingerprint = config.sshKeyFingerprint;
    result.keySource = config.sshKeyPath ? 'file' : 'agent_or_generated';
  } else {
    result.keySource = 'none';
    result.message = 'No SSH key configured. Multi-device sync requires an SSH key. Run: ssh-keygen -t ed25519';
  }

  if (config.syncPending) {
    result.message = 'Sync server was unreachable. Will retry on next launch.';
  }

  // Check if an SSH key has appeared since bootstrap (nudge)
  if (!config.sshKeyPath && !config.sshKeyFingerprint) {
    const sshDir = path.join(process.env.HOME ?? '', '.ssh');
    const hasSSHKey = fs.existsSync(path.join(sshDir, 'id_ed25519.pub')) ||
                      fs.existsSync(path.join(sshDir, 'id_rsa.pub'));
    if (hasSSHKey) {
      result.nudge = 'SSH key detected on this system. Switch to it for multi-device sync: chaoskb-mcp config rotate-key';
    }
  }

  return JSON.stringify(result, null, 2);
}

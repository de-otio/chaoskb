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

  // Fetch device count, rotation state, and pending invites from server
  if (config.endpoint && config.syncEnabled) {
    try {
      const { createSyncClient } = await import('./sync-client.js');
      const { signedFetch } = await createSyncClient();

      const [devicesResp, invitesResp] = await Promise.allSettled([
        signedFetch('GET', '/v1/devices'),
        signedFetch('GET', '/v1/invites'),
      ]);

      if (devicesResp.status === 'fulfilled' && devicesResp.value.ok) {
        const data = await devicesResp.value.json() as { devices: Array<{ fingerprint: string; registeredAt: string }> };
        result.deviceCount = data.devices.length;
        result.devices = data.devices.map((d) => ({
          fingerprint: d.fingerprint,
          registeredAt: d.registeredAt,
        }));
      }

      if (invitesResp.status === 'fulfilled' && invitesResp.value.ok) {
        const data = await invitesResp.value.json() as { invites: Array<{ id: string; project: string; status: string }> };
        const pending = data.invites.filter((i) => i.status === 'pending');
        if (pending.length > 0) {
          result.pendingInvites = pending.length;
        }
      }
    } catch {
      // Server unreachable — skip remote info
    }
  }

  return JSON.stringify(result, null, 2);
}

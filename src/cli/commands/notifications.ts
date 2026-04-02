import * as path from 'node:path';
import * as os from 'node:os';
import { loadConfig } from './setup.js';

/**
 * Helper to create an authenticated HTTP client for the sync server.
 */
async function createSyncClient(): Promise<{
  signedFetch: (method: string, urlPath: string, body?: Uint8Array) => Promise<Response>;
}> {
  const config = await loadConfig();
  if (!config) {
    console.error('ChaosKB is not set up. Run `chaoskb-mcp setup` first.');
    process.exit(1);
  }

  if (!config.endpoint) {
    console.error('Sync is not configured. Run `chaoskb-mcp setup-sync` first.');
    process.exit(1);
  }

  const endpoint = config.endpoint.replace(/\/+$/, '');
  const sshKeyPath = config.sshKeyPath ?? path.join(os.homedir(), '.ssh', 'id_ed25519');

  const { SSHSigner } = await import('../../sync/ssh-signer.js');
  const signer = new SSHSigner(sshKeyPath);
  let sequence = 1;

  const signedFetch = async (method: string, urlPath: string, body?: Uint8Array): Promise<Response> => {
    const seq = sequence++;
    const result = await signer.signRequest(method, urlPath, seq, body);

    const headers: Record<string, string> = {
      Authorization: result.authorization,
      'X-ChaosKB-Timestamp': result.timestamp,
      'X-ChaosKB-Sequence': String(result.sequence),
      'X-ChaosKB-PublicKey': result.publicKey,
    };

    return fetch(`${endpoint}${urlPath}`, {
      method,
      headers,
      body: body ?? undefined,
      signal: AbortSignal.timeout(30_000),
    });
  };

  return { signedFetch };
}

interface Notification {
  id: string;
  type: string;
  deviceInfo?: {
    hostname?: string;
    platform?: string;
    arch?: string;
    osVersion?: string;
    deviceModel?: string | null;
    location?: string | null;
  };
  timestamp: string;
}

/**
 * `chaoskb-mcp notifications list`
 *
 * Shows unacknowledged notifications (new device linked, device revoked, etc.)
 */
export async function notificationsListCommand(): Promise<void> {
  const { signedFetch } = await createSyncClient();

  const resp = await signedFetch('GET', '/v1/notifications');
  if (!resp.ok) {
    const err = await resp.text();
    console.error(`Failed to fetch notifications: ${resp.status} ${err}`);
    process.exit(1);
  }

  const data = await resp.json() as { notifications: Notification[] };

  if (data.notifications.length === 0) {
    console.log('');
    console.log('  No new notifications.');
    console.log('');
    return;
  }

  console.log('');
  console.log(`  ${data.notifications.length} notification(s)`);
  console.log('  ========================');

  for (const n of data.notifications) {
    console.log('');
    const time = new Date(n.timestamp).toLocaleString();
    const type = n.type === 'device_linked' ? 'New device linked'
      : n.type === 'device_revoked' ? 'Device revoked'
      : n.type === 'key_rotated' ? 'Key rotated'
      : n.type;

    console.log(`  ${type}  (${time})`);

    if (n.deviceInfo) {
      const d = n.deviceInfo;
      if (d.hostname) console.log(`    Hostname: ${d.hostname}`);
      if (d.platform && d.osVersion) console.log(`    OS:       ${d.platform} ${d.osVersion} (${d.arch ?? 'unknown'})`);
      if (d.deviceModel) console.log(`    Device:   ${d.deviceModel}`);
      if (d.location) console.log(`    Location: ${d.location}`);
    }

    console.log(`    ID: ${n.id}`);
  }
  console.log('');
}

/**
 * `chaoskb-mcp notifications dismiss [id]`
 *
 * Dismiss a specific notification or all notifications.
 */
export async function notificationsDismissCommand(id?: string): Promise<void> {
  const { signedFetch } = await createSyncClient();

  if (id) {
    const urlPath = `/v1/notifications/${encodeURIComponent(id)}/dismiss`;
    const resp = await signedFetch('POST', urlPath);
    if (!resp.ok) {
      const err = await resp.text();
      console.error(`Failed to dismiss notification: ${resp.status} ${err}`);
      process.exit(1);
    }
    console.log('  Notification dismissed.');
  } else {
    // Dismiss all: fetch list, then dismiss each
    const listResp = await signedFetch('GET', '/v1/notifications');
    if (!listResp.ok) {
      console.error(`Failed to fetch notifications: ${listResp.status}`);
      process.exit(1);
    }

    const data = await listResp.json() as { notifications: Notification[] };
    if (data.notifications.length === 0) {
      console.log('  No notifications to dismiss.');
      return;
    }

    for (const n of data.notifications) {
      const urlPath = `/v1/notifications/${encodeURIComponent(n.id)}/dismiss`;
      await signedFetch('POST', urlPath);
    }
    console.log(`  ${data.notifications.length} notification(s) dismissed.`);
  }
}

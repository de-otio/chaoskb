import { createSyncClient } from './sync-client.js';

export interface DevicesRemoveInput {
  fingerprint: string;
}

/**
 * MCP tool: devices_remove
 *
 * Removes a registered device by fingerprint. The device will stop syncing
 * on its next attempt.
 */
export async function handleDevicesRemove(input: DevicesRemoveInput): Promise<{
  status: string;
  fingerprint: string;
  message: string;
}> {
  if (!input.fingerprint) {
    throw new Error('fingerprint is required');
  }

  const { signedFetch } = await createSyncClient();

  const resp = await signedFetch('DELETE', `/v1/devices/${encodeURIComponent(input.fingerprint)}`);
  if (!resp.ok) {
    const err = await resp.text();
    if (resp.status === 404) {
      throw new Error(`Device with fingerprint ${input.fingerprint} not found.`);
    }
    throw new Error(`Failed to remove device: ${resp.status} ${err}`);
  }

  return {
    status: 'removed',
    fingerprint: input.fingerprint,
    message: `Device ${input.fingerprint} removed. It will stop syncing on its next attempt.`,
  };
}

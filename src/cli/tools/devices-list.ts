import { createSyncClient } from './sync-client.js';

export interface DevicesListInput {
  // No required inputs
}

interface DeviceInfo {
  fingerprint: string;
  registeredAt: string;
  metadata?: Record<string, unknown>;
}

/**
 * MCP tool: devices_list
 *
 * Lists all registered devices for the current account.
 */
export async function handleDevicesList(_input: DevicesListInput): Promise<{
  devices: DeviceInfo[];
  count: number;
}> {
  const { signedFetch } = await createSyncClient();

  const resp = await signedFetch('GET', '/v1/devices');
  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`Failed to list devices: ${resp.status} ${err}`);
  }

  const data = await resp.json() as { devices: DeviceInfo[] };

  return {
    devices: data.devices,
    count: data.devices.length,
  };
}

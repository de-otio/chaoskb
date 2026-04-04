import * as crypto from 'node:crypto';
import { createSyncClient } from './sync-client.js';

export interface DeviceLinkConfirmInput {
  linkCode: string;
}

/**
 * MCP tool: device_link_confirm
 *
 * Confirms a device link by submitting the link code from the new device.
 * The existing device will then wrap the master key for this device.
 */
export async function handleDeviceLinkConfirm(input: DeviceLinkConfirmInput): Promise<{
  status: string;
  message: string;
}> {
  if (!input.linkCode) {
    throw new Error('linkCode is required');
  }

  const { signedFetch } = await createSyncClient();

  const codeHash = crypto.createHash('sha256').update(input.linkCode).digest('hex');
  const body = JSON.stringify({ codeHash });
  const bodyBytes = new TextEncoder().encode(body);

  const resp = await signedFetch('POST', '/v1/link-confirm', bodyBytes);
  if (!resp.ok) {
    const err = await resp.text();
    if (resp.status === 404) {
      throw new Error('Link code not found or expired. Ask the other device to generate a new code.');
    }
    if (resp.status === 429) {
      throw new Error('Too many attempts. The link code has been invalidated. Generate a new one.');
    }
    throw new Error(`Failed to confirm link: ${resp.status} ${err}`);
  }

  const data = await resp.json() as { status: string };

  return {
    status: data.status ?? 'confirmed',
    message: 'Device linked successfully. The existing device will wrap the master key for you.',
  };
}

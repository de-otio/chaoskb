import * as crypto from 'node:crypto';
import { createSyncClient } from './sync-client.js';

const BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

function generateLinkCode(length: number): string {
  const bytes = crypto.randomBytes(length);
  let code = '';
  for (let i = 0; i < length; i++) {
    code += BASE62[bytes[i] % 62];
  }
  return code;
}

export type DeviceLinkStartInput = Record<string, never>;

/**
 * MCP tool: device_link_start
 *
 * Generates a device link code and registers its hash with the sync server.
 * The user should share this code with their new device.
 */
export async function handleDeviceLinkStart(_input: DeviceLinkStartInput): Promise<{
  linkCode: string;
  expiresInMinutes: number;
  instructions: string;
}> {
  const { signedFetch } = await createSyncClient();

  const linkCode = generateLinkCode(10);
  const codeHash = crypto.createHash('sha256').update(linkCode).digest('hex');

  const body = JSON.stringify({ codeHash });
  const bodyBytes = new TextEncoder().encode(body);

  const resp = await signedFetch('POST', '/v1/link-code', bodyBytes);
  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`Failed to create link code: ${resp.status} ${err}`);
  }

  return {
    linkCode,
    expiresInMinutes: 5,
    instructions: `On the new device, tell your agent: "confirm device link with code ${linkCode}"`,
  };
}

import { createSyncClient } from './sync-client.js';

export interface RevokeAllInput {
  confirmation: string;
}

/**
 * MCP tool: revoke_all
 *
 * Revokes all device keys for the current account. This is an emergency
 * action — all devices will lose sync access and must re-register.
 *
 * Requires confirmation string "REVOKE ALL" to prevent accidental invocation.
 */
export async function handleRevokeAll(input: RevokeAllInput): Promise<{
  status: string;
  message: string;
}> {
  if (input.confirmation !== 'REVOKE ALL') {
    throw new Error(
      'Safety check failed. To revoke all device keys, pass confirmation: "REVOKE ALL". ' +
      'This action cannot be undone — all devices will lose sync access.',
    );
  }

  const { signedFetch } = await createSyncClient();

  const resp = await signedFetch('POST', '/v1/revoke-all');
  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`Failed to revoke keys: ${resp.status} ${err}`);
  }

  return {
    status: 'revoked',
    message: 'All device keys have been revoked. All devices must re-register to sync.',
  };
}

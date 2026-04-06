import * as path from 'node:path';
import * as os from 'node:os';
import { loadConfig } from '../commands/setup.js';

export interface SyncClient {
  endpoint: string;
  signedFetch: (method: string, urlPath: string, body?: Uint8Array) => Promise<Response>;
}

/**
 * Create an authenticated HTTP client for the sync server.
 * Shared by all device management MCP tools.
 */
export async function createSyncClient(): Promise<SyncClient> {
  const config = await loadConfig();
  if (!config?.endpoint) {
    throw new Error('Sync is not configured. Run `chaoskb-mcp setup-sync` first.');
  }

  const endpoint = config.endpoint.replace(/\/+$/, '');
  const sshKeyPath = config.sshKeyPath ?? path.join(os.homedir(), '.ssh', 'id_ed25519');

  const { SSHSigner } = await import('../../sync/ssh-signer.js');
  const { SequenceCounter } = await import('../../sync/sequence.js');
  const signer = new SSHSigner(sshKeyPath);
  const sequence = new SequenceCounter();

  const signedFetch = async (method: string, urlPath: string, body?: Uint8Array): Promise<Response> => {
    const seq = sequence.next();
    const result = await signer.signRequest(method, urlPath, seq, body);

    const headers: Record<string, string> = {
      Authorization: result.authorization,
      'X-ChaosKB-Timestamp': result.timestamp,
      'X-ChaosKB-Sequence': String(result.sequence),
      'X-ChaosKB-PublicKey': result.publicKey,
    };

    if (body) {
      headers['Content-Type'] = 'application/json';
    }

    return fetch(`${endpoint}${urlPath}`, {
      method,
      headers,
      body: body ?? undefined,
      signal: AbortSignal.timeout(30_000),
    });
  };

  return { endpoint, signedFetch };
}

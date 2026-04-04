import { createSyncClient } from './sync-client.js';

export interface AuditLogInput {
  limit?: number;
}

interface AuditEvent {
  timestamp: string;
  event: string;
  fingerprint?: string;
  metadata?: Record<string, unknown>;
}

/**
 * MCP tool: audit_log
 *
 * Returns the device audit log for the current account.
 */
export async function handleAuditLog(input: AuditLogInput): Promise<{
  events: AuditEvent[];
  count: number;
}> {
  const { signedFetch } = await createSyncClient();

  const limit = input.limit ?? 50;
  const resp = await signedFetch('GET', `/v1/audit-log?limit=${limit}`);
  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`Failed to fetch audit log: ${resp.status} ${err}`);
  }

  const data = await resp.json() as { events: AuditEvent[] };

  return {
    events: data.events,
    count: data.events.length,
  };
}

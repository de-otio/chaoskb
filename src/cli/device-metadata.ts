import * as os from 'node:os';
import { execFile } from 'node:child_process';

export interface DeviceMetadata {
  hostname: string;
  platform: string;
  arch: string;
  osVersion: string;
  deviceModel: string | null;
}

/**
 * E5: Collect device metadata for registration.
 *
 * Gathers hostname, OS, architecture, OS version, and device model.
 * All fields degrade gracefully — never throws.
 */
export async function collectDeviceMetadata(): Promise<DeviceMetadata> {
  const hostname = os.hostname();
  const platform = os.platform();
  const arch = os.arch();
  const osVersion = os.release();
  const deviceModel = await detectDeviceModel(platform);

  return { hostname, platform, arch, osVersion, deviceModel };
}

async function detectDeviceModel(platform: string): Promise<string | null> {
  try {
    if (platform === 'darwin') {
      // macOS: use system_profiler
      const output = await execCommand('system_profiler', ['SPHardwareDataType', '-detailLevel', 'mini']);
      const match = output.match(/Model Name:\s*(.+)/);
      return match ? match[1].trim() : null;
    }

    if (platform === 'linux') {
      // Linux: read DMI product name
      const { readFile } = await import('node:fs/promises');
      try {
        const model = await readFile('/sys/class/dmi/id/product_name', 'utf-8');
        const trimmed = model.trim();
        // Filter out generic values
        if (trimmed && trimmed !== 'System Product Name' && trimmed !== 'To Be Filled By O.E.M.') {
          return trimmed;
        }
      } catch {
        // File not readable (containers, VMs without DMI)
      }
      return null;
    }

    return null;
  } catch {
    return null;
  }
}

function execCommand(command: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(command, args, { timeout: 5000 }, (error, stdout) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(stdout);
    });
  });
}

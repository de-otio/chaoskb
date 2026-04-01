import { describe, it, expect } from 'vitest';
import { collectDeviceMetadata } from '../device-metadata.js';

describe('collectDeviceMetadata', () => {
  it('should return hostname, platform, arch, osVersion', async () => {
    const metadata = await collectDeviceMetadata();

    expect(metadata.hostname).toBeTruthy();
    expect(typeof metadata.hostname).toBe('string');
    expect(metadata.platform).toBeTruthy();
    expect(['darwin', 'linux', 'win32']).toContain(metadata.platform);
    expect(metadata.arch).toBeTruthy();
    expect(metadata.osVersion).toBeTruthy();
    // deviceModel may be null on CI or VMs
    expect(metadata.deviceModel === null || typeof metadata.deviceModel === 'string').toBe(true);
  });

  it('should collect deviceModel on macOS', async () => {
    const metadata = await collectDeviceMetadata();
    if (metadata.platform === 'darwin') {
      // On real macOS, device model should be detected
      expect(metadata.deviceModel).toBeTruthy();
    }
  });
});

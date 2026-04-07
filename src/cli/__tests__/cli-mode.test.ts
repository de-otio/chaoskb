import { describe, it, expect } from 'vitest';
import { shouldStartMcpServer } from '../index.js';

describe('shouldStartMcpServer', () => {
  it('returns true when stdin is not TTY and no args', () => {
    expect(shouldStartMcpServer(false, [])).toBe(true);
  });

  it('returns true when stdin is not TTY and only flag-style args', () => {
    expect(shouldStartMcpServer(false, ['--project'])).toBe(true);
  });

  it('returns true when stdin is not TTY and --project has a value arg', () => {
    // --project consumes the next arg as its value, not as a CLI command
    expect(shouldStartMcpServer(false, ['--project', 'myproject'])).toBe(true);
  });

  it('returns false when stdin is not TTY but a command arg is present', () => {
    expect(shouldStartMcpServer(false, ['status'])).toBe(false);
  });

  it('returns false when stdin is not TTY but --version flag is present', () => {
    expect(shouldStartMcpServer(false, ['--version'])).toBe(false);
  });

  it('returns false when stdin is not TTY but -V flag is present', () => {
    expect(shouldStartMcpServer(false, ['-V'])).toBe(false);
  });

  it('returns false when stdin is not TTY but --help flag is present', () => {
    expect(shouldStartMcpServer(false, ['--help'])).toBe(false);
  });

  it('returns false when stdin is not TTY but -h flag is present', () => {
    expect(shouldStartMcpServer(false, ['-h'])).toBe(false);
  });

  it('returns false when stdin is TTY with no args', () => {
    expect(shouldStartMcpServer(true, [])).toBe(false);
  });

  it('returns false when stdin is TTY with a command arg', () => {
    expect(shouldStartMcpServer(true, ['setup'])).toBe(false);
  });

  it('returns false when stdin is TTY with --version', () => {
    expect(shouldStartMcpServer(true, ['--version'])).toBe(false);
  });

  it('returns false when stdin is not TTY with mixed flags and command', () => {
    expect(shouldStartMcpServer(false, ['--project', 'myproject', 'status'])).toBe(false);
  });
});

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { DatabaseManager } from '../database-manager.js';

describe('DatabaseManager', () => {
  let tmpDir: string;
  let manager: DatabaseManager;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chaoskb-manager-test-'));
    manager = new DatabaseManager(tmpDir);
  });

  afterEach(() => {
    manager.closeAll();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('getPersonalDb', () => {
    it('should create and return a personal database', () => {
      const db = manager.getPersonalDb();
      expect(db).toBeDefined();
      expect(db.sources).toBeDefined();
      expect(db.chunks).toBeDefined();
      expect(db.syncStatus).toBeDefined();
      expect(db.embeddingIndex).toBeDefined();
    });

    it('should return the same instance on subsequent calls', () => {
      const db1 = manager.getPersonalDb();
      const db2 = manager.getPersonalDb();
      expect(db1).toBe(db2);
    });

    it('should create the database file at the correct path', () => {
      manager.getPersonalDb();
      const dbPath = path.join(tmpDir, 'local.db');
      expect(fs.existsSync(dbPath)).toBe(true);
    });

    it.skipIf(process.platform === 'win32')('should set correct file permissions on the database file', () => {
      manager.getPersonalDb();
      const dbPath = path.join(tmpDir, 'local.db');
      const stats = fs.statSync(dbPath);
      // Check owner read/write only (0o600)
      const mode = stats.mode & 0o777;
      expect(mode).toBe(0o600);
    });
  });

  describe('getProjectDb', () => {
    it('should create and return a project database', () => {
      const db = manager.getProjectDb('my-project');
      expect(db).toBeDefined();
    });

    it('should return the same instance on subsequent calls', () => {
      const db1 = manager.getProjectDb('my-project');
      const db2 = manager.getProjectDb('my-project');
      expect(db1).toBe(db2);
    });

    it('should create the database file in the project directory', () => {
      manager.getProjectDb('my-project');
      const dbPath = path.join(tmpDir, 'projects', 'my-project', 'local.db');
      expect(fs.existsSync(dbPath)).toBe(true);
    });

    it.skipIf(process.platform === 'win32')('should create the project directory with correct permissions', () => {
      manager.getProjectDb('my-project');
      const projectDir = path.join(tmpDir, 'projects', 'my-project');
      const stats = fs.statSync(projectDir);
      const mode = stats.mode & 0o777;
      expect(mode).toBe(0o700);
    });

    it.skipIf(process.platform === 'win32')('should set correct file permissions on the database file', () => {
      manager.getProjectDb('my-project');
      const dbPath = path.join(tmpDir, 'projects', 'my-project', 'local.db');
      const stats = fs.statSync(dbPath);
      const mode = stats.mode & 0o777;
      expect(mode).toBe(0o600);
    });

    it('should reject invalid project names', () => {
      expect(() => manager.getProjectDb('invalid name')).toThrow(/Invalid project name/);
      expect(() => manager.getProjectDb('path/traversal')).toThrow(/Invalid project name/);
      expect(() => manager.getProjectDb('dots..bad')).toThrow(/Invalid project name/);
      expect(() => manager.getProjectDb('')).toThrow(/Invalid project name/);
    });

    it('should accept valid project names', () => {
      expect(() => manager.getProjectDb('my-project')).not.toThrow();
      expect(() => manager.getProjectDb('my_project')).not.toThrow();
      expect(() => manager.getProjectDb('project123')).not.toThrow();
      expect(() => manager.getProjectDb('CamelCase')).not.toThrow();
    });

    it('should create separate databases for different projects', () => {
      const db1 = manager.getProjectDb('project-a');
      const db2 = manager.getProjectDb('project-b');
      expect(db1).not.toBe(db2);
    });
  });

  describe('listProjects', () => {
    it('should return empty array when no projects exist', () => {
      expect(manager.listProjects()).toEqual([]);
    });

    it('should list all projects with metadata', () => {
      // Create some projects with data
      const db1 = manager.getProjectDb('alpha');
      db1.sources.insert({
        id: 'src1',
        url: 'https://example.com',
        title: 'Test',
        tags: [],
        chunkCount: 0,
        blobSizeBytes: 0,
      });

      manager.getProjectDb('beta');

      const projects = manager.listProjects();
      expect(projects).toHaveLength(2);

      const names = projects.map((p) => p.name).sort();
      expect(names).toEqual(['alpha', 'beta']);

      const alpha = projects.find((p) => p.name === 'alpha')!;
      expect(alpha.sourceCount).toBe(1);
      expect(alpha.sizeBytes).toBeGreaterThan(0);
      expect(alpha.path).toBe(path.join(tmpDir, 'projects', 'alpha'));
    });
  });

  describe('deleteProject', () => {
    it('should delete a project and its database', () => {
      manager.getProjectDb('doomed');
      const projectDir = path.join(tmpDir, 'projects', 'doomed');
      expect(fs.existsSync(projectDir)).toBe(true);

      const result = manager.deleteProject('doomed');
      expect(result).toBe(true);
      expect(fs.existsSync(projectDir)).toBe(false);
    });

    it('should return false for non-existent project', () => {
      expect(manager.deleteProject('nonexistent')).toBe(false);
    });

    it('should reject invalid project names', () => {
      expect(() => manager.deleteProject('bad name')).toThrow(/Invalid project name/);
    });

    it('should close the database connection before deleting', () => {
      const db = manager.getProjectDb('to-delete');
      // Insert data to make sure the DB is active
      db.sources.insert({
        id: 'src1',
        url: 'https://example.com',
        title: 'Test',
        tags: [],
        chunkCount: 0,
        blobSizeBytes: 0,
      });

      // Should not throw even though DB was in use
      expect(() => manager.deleteProject('to-delete')).not.toThrow();
    });
  });

  describe('closeAll', () => {
    it('should close all open databases', () => {
      manager.getPersonalDb();
      manager.getProjectDb('proj1');
      manager.getProjectDb('proj2');

      // Should not throw
      expect(() => manager.closeAll()).not.toThrow();
    });

    it('should allow reopening databases after close', () => {
      manager.getPersonalDb();
      manager.closeAll();

      // Should be able to open again
      const db = manager.getPersonalDb();
      expect(db).toBeDefined();
    });
  });
});

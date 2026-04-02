import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import type { IDatabaseManager, IDatabase } from './types.js';
import { KBDatabase } from './kb-database.js';

const PROJECT_NAME_RE = /^[a-zA-Z0-9_-]+$/;

export class DatabaseManager implements IDatabaseManager {
  private readonly baseDir: string;
  private readonly databases: Map<string, IDatabase> = new Map();

  constructor(baseDir?: string) {
    this.baseDir = baseDir ?? path.join(os.homedir(), '.chaoskb');

    if (!fs.existsSync(this.baseDir)) {
      fs.mkdirSync(this.baseDir, { recursive: true, mode: 0o700 });
    }
  }

  getPersonalDb(): IDatabase {
    const key = '__personal__';
    let db = this.databases.get(key);
    if (db) return db;

    const dbPath = path.join(this.baseDir, 'local.db');
    db = new KBDatabase({ path: dbPath });
    this.databases.set(key, db);
    return db;
  }

  getProjectDb(projectName: string): IDatabase {
    if (!PROJECT_NAME_RE.test(projectName)) {
      throw new Error(
        `Invalid project name "${projectName}": only alphanumeric characters, hyphens, and underscores are allowed`,
      );
    }

    const key = `project:${projectName}`;
    let db = this.databases.get(key);
    if (db) return db;

    const projectDir = path.join(this.baseDir, 'projects', projectName);
    if (!fs.existsSync(projectDir)) {
      fs.mkdirSync(projectDir, { recursive: true, mode: 0o700 });
    }

    const dbPath = path.join(projectDir, 'local.db');
    db = new KBDatabase({ path: dbPath, projectName });
    this.databases.set(key, db);
    return db;
  }

  getNamedKBDb(kbName: string): IDatabase {
    if (!PROJECT_NAME_RE.test(kbName)) {
      throw new Error(
        `Invalid KB name "${kbName}": only alphanumeric characters, hyphens, and underscores are allowed`,
      );
    }

    const key = `kb:${kbName}`;
    let db = this.databases.get(key);
    if (db) return db;

    const kbDir = path.join(this.baseDir, kbName, 'db');
    if (!fs.existsSync(kbDir)) {
      fs.mkdirSync(kbDir, { recursive: true, mode: 0o700 });
    }

    const dbPath = path.join(kbDir, 'local.db');
    db = new KBDatabase({ path: dbPath });
    this.databases.set(key, db);
    return db;
  }

  listProjects(): { name: string; path: string; sizeBytes: number; sourceCount: number }[] {
    const projectsDir = path.join(this.baseDir, 'projects');
    if (!fs.existsSync(projectsDir)) {
      return [];
    }

    const entries = fs.readdirSync(projectsDir, { withFileTypes: true });
    const results: { name: string; path: string; sizeBytes: number; sourceCount: number }[] = [];

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;

      const projectDir = path.join(projectsDir, entry.name);
      const dbPath = path.join(projectDir, 'local.db');

      if (!fs.existsSync(dbPath)) continue;

      const stats = fs.statSync(dbPath);
      let sourceCount = 0;

      // Open the DB temporarily to get the source count
      try {
        const db = this.getProjectDb(entry.name);
        sourceCount = db.sources.count();
      } catch {
        // If we can't open the DB, just report 0 sources
      }

      results.push({
        name: entry.name,
        path: projectDir,
        sizeBytes: stats.size,
        sourceCount,
      });
    }

    return results;
  }

  deleteProject(projectName: string): boolean {
    if (!PROJECT_NAME_RE.test(projectName)) {
      throw new Error(
        `Invalid project name "${projectName}": only alphanumeric characters, hyphens, and underscores are allowed`,
      );
    }

    const projectDir = path.join(this.baseDir, 'projects', projectName);
    if (!fs.existsSync(projectDir)) {
      return false;
    }

    // Close the DB if it's open
    const key = `project:${projectName}`;
    const db = this.databases.get(key);
    if (db) {
      db.close();
      this.databases.delete(key);
    }

    fs.rmSync(projectDir, { recursive: true, force: true });
    return true;
  }

  closeAll(): void {
    for (const db of this.databases.values()) {
      db.close();
    }
    this.databases.clear();
  }
}

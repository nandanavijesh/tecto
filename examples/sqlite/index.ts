/**
 * TECTO — SQLite Persistent Key Store Example
 *
 * Shows how to implement `KeyStoreAdapter` backed by SQLite
 * so keys survive process restarts. Uses Bun's built-in `bun:sqlite`.
 *
 * Run: bun run examples/sqlite/index.ts
 *
 * Dependencies: None (bun:sqlite is built into Bun)
 */

import { Database } from "bun:sqlite";
import { unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { KeyStoreAdapter } from "../../src/index.js";
import { assertEntropy, generateSecureKey, MemoryKeyStore, TectoCoder } from "../../src/index.js";

class SqliteKeyStore implements KeyStoreAdapter {
  private db: Database;
  private mem: MemoryKeyStore;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.mem = new MemoryKeyStore();
    this.db.run(`
      CREATE TABLE IF NOT EXISTS tecto_keys (
        id TEXT PRIMARY KEY, secret BLOB NOT NULL,
        is_current INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `);
    this.loadFromDb();
  }

  private loadFromDb(): void {
    const rows = this.db
      .query("SELECT id, secret, is_current FROM tecto_keys ORDER BY created_at ASC")
      .all() as Array<{ id: string; secret: Buffer; is_current: number }>;
    for (const row of rows) {
      const key = new Uint8Array(row.secret);
      this.mem.addKey(row.id, key);
      if (row.is_current === 1) {
        this.mem.rotate(row.id, key);
      }
    }
  }

  addKey(id: string, secret: Uint8Array): void {
    assertEntropy(secret);
    this.mem.addKey(id, secret);
    const cur = this.mem.getCurrentKeyId() === id ? 1 : 0;
    this.db.run("INSERT INTO tecto_keys (id, secret, is_current) VALUES (?, ?, ?)", [
      id,
      Buffer.from(secret),
      cur,
    ]);
  }

  rotate(newId: string, newSecret: Uint8Array): void {
    assertEntropy(newSecret);
    this.db.run("UPDATE tecto_keys SET is_current = 0");
    this.mem.rotate(newId, newSecret);
    this.db.run("INSERT INTO tecto_keys (id, secret, is_current) VALUES (?, ?, 1)", [
      newId,
      Buffer.from(newSecret),
    ]);
  }

  getKey(id: string): Uint8Array {
    return this.mem.getKey(id);
  }
  removeKey(id: string): void {
    this.mem.removeKey(id);
    this.db.run("DELETE FROM tecto_keys WHERE id = ?", [id]);
  }
  getCurrentKeyId(): string {
    return this.mem.getCurrentKeyId();
  }
  get size(): number {
    return this.mem.size;
  }
  close(): void {
    this.db.close();
  }
}

console.log("╔══════════════════════════════════════════════════════╗");
console.log("║      TECTO — SQLite KeyStoreAdapter Example         ║");
console.log("╚══════════════════════════════════════════════════════╝\n");

const DB_PATH = join(tmpdir(), `tecto-example-${Date.now()}.db`);
const store = new SqliteKeyStore(DB_PATH);

store.addKey("key-v1", generateSecureKey());
store.rotate("key-v2", generateSecureKey());
console.log("  Current key:", store.getCurrentKeyId(), "\n");

const coder = new TectoCoder(store);
const token = coder.encrypt({ userId: 1, session: "abc" }, { expiresIn: "24h" });
console.log("  Token:", `${token.slice(0, 60)}...\n`);

const payload = coder.decrypt<{ userId: number; session: string }>(token);
console.log("  Decrypted:", JSON.stringify(payload, null, 2), "\n");

console.log("─── Simulate Restart ───\n");
store.close();
const fresh = new SqliteKeyStore(DB_PATH);
const freshCoder = new TectoCoder(fresh);
const restored = freshCoder.decrypt<{ userId: number; session: string }>(token);
console.log("  ✅ After restart:", restored.userId, restored.session, "\n");
fresh.close();
try {
  unlinkSync(DB_PATH);
} catch {}

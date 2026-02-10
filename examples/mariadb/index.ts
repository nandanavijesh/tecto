/**
 * TECTO — MariaDB/MySQL Persistent Key Store Example
 *
 * Shows how to implement `KeyStoreAdapter` backed by MariaDB/MySQL.
 * Keys persist across restarts and work across multiple server instances.
 *
 * Run: bun run examples/mariadb/index.ts
 *
 * Dependencies: bun add mysql2
 *
 * Environment variables:
 *   DB_HOST (default: localhost), DB_PORT (default: 3306),
 *   DB_USER (default: root), DB_PASSWORD (default: ""),
 *   DB_NAME (default: tecto_example)
 */

import type { KeyStoreAdapter } from "../../src/index.js";
import { assertEntropy, generateSecureKey, MemoryKeyStore, TectoCoder } from "../../src/index.js";

interface DbConfig {
  host: string;
  port: number;
  user: string;
  password: string;
  database: string;
}

class MariaDbKeyStore implements KeyStoreAdapter {
  private config: DbConfig;
  private mem: MemoryKeyStore;

  constructor(config: DbConfig) {
    this.config = config;
    this.mem = new MemoryKeyStore();
  }

  async initialize(): Promise<void> {
    const mysql = await import("mysql2/promise");
    const conn = await mysql.createConnection(this.config);
    await conn.execute(`
      CREATE TABLE IF NOT EXISTS tecto_keys (
        id VARCHAR(255) PRIMARY KEY, secret VARBINARY(32) NOT NULL,
        is_current TINYINT NOT NULL DEFAULT 0,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB
    `);
    const [rows] = await conn.execute(
      "SELECT id, secret, is_current FROM tecto_keys ORDER BY created_at ASC",
    );
    for (const row of rows as Array<{ id: string; secret: Buffer; is_current: number }>) {
      const key = new Uint8Array(row.secret);
      this.mem.addKey(row.id, key);
      if (row.is_current === 1) {
        this.mem.rotate(row.id, key);
      }
    }
    await conn.end();
  }

  async addKey(id: string, secret: Uint8Array): Promise<void> {
    assertEntropy(secret);
    this.mem.addKey(id, secret);
    const mysql = await import("mysql2/promise");
    const conn = await mysql.createConnection(this.config);
    const cur = this.mem.getCurrentKeyId() === id ? 1 : 0;
    await conn.execute("INSERT INTO tecto_keys (id, secret, is_current) VALUES (?, ?, ?)", [
      id,
      Buffer.from(secret),
      cur,
    ]);
    await conn.end();
  }

  async rotate(newId: string, newSecret: Uint8Array): Promise<void> {
    assertEntropy(newSecret);
    const mysql = await import("mysql2/promise");
    const conn = await mysql.createConnection(this.config);
    await conn.beginTransaction();
    try {
      await conn.execute("UPDATE tecto_keys SET is_current = 0");
      await conn.execute("INSERT INTO tecto_keys (id, secret, is_current) VALUES (?, ?, 1)", [
        newId,
        Buffer.from(newSecret),
      ]);
      await conn.commit();
    } catch (err) {
      await conn.rollback();
      throw err;
    }
    this.mem.rotate(newId, newSecret);
    await conn.end();
  }

  async removeKey(id: string): Promise<void> {
    this.mem.removeKey(id);
    const mysql = await import("mysql2/promise");
    const conn = await mysql.createConnection(this.config);
    await conn.execute("DELETE FROM tecto_keys WHERE id = ?", [id]);
    await conn.end();
  }

  getKey(id: string): Uint8Array {
    return this.mem.getKey(id);
  }
  getCurrentKeyId(): string {
    return this.mem.getCurrentKeyId();
  }
  get size(): number {
    return this.mem.size;
  }
}

const config: DbConfig = {
  host: process.env.DB_HOST ?? "localhost",
  port: Number.parseInt(process.env.DB_PORT ?? "3306", 10),
  user: process.env.DB_USER ?? "root",
  password: process.env.DB_PASSWORD ?? "",
  database: process.env.DB_NAME ?? "tecto_example",
};

console.log("╔══════════════════════════════════════════════════════╗");
console.log("║     TECTO — MariaDB KeyStoreAdapter Example         ║");
console.log("╚══════════════════════════════════════════════════════╝\n");

try {
  const store = new MariaDbKeyStore(config);
  await store.initialize();
  await store.addKey("key-v1", generateSecureKey());
  await store.rotate("key-v2", generateSecureKey());

  const coder = new TectoCoder(store);
  const token = coder.encrypt({ userId: 1 }, { expiresIn: "7d" });
  console.log("  Token:", `${token.slice(0, 60)}...\n`);
  console.log("  Decrypted:", JSON.stringify(coder.decrypt(token), null, 2), "\n");

  const fresh = new MariaDbKeyStore(config);
  await fresh.initialize();
  const r = new TectoCoder(fresh).decrypt<{ userId: number }>(token);
  console.log("  ✅ After restart:", r.userId, "\n");
} catch (err) {
  if ((err as NodeJS.ErrnoException).code === "ECONNREFUSED") {
    console.log("  ⚠️  MariaDB not running. Start with Docker:\n");
    console.log("    docker run -d -p 3306:3306 -e MYSQL_ALLOW_EMPTY_PASSWORD=yes \\");
    console.log("      -e MYSQL_DATABASE=tecto_example mariadb:latest\n");
  } else {
    throw err;
  }
}

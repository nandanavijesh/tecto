/**
 * TECTO — PostgreSQL Persistent Key Store Example
 *
 * Shows how to implement `KeyStoreAdapter` backed by PostgreSQL.
 * Keys persist across restarts and work across multiple server instances.
 *
 * Run: bun run examples/postgres/index.ts
 *
 * Dependencies: bun add pg @types/pg
 *
 * Environment variables:
 *   DB_HOST (default: localhost), DB_PORT (default: 5432),
 *   DB_USER (default: postgres), DB_PASSWORD (default: ""),
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

class PostgresKeyStore implements KeyStoreAdapter {
  private config: DbConfig;
  private mem: MemoryKeyStore;

  constructor(config: DbConfig) {
    this.config = config;
    this.mem = new MemoryKeyStore();
  }

  async initialize(): Promise<void> {
    const pg = await import("pg");
    const client = new pg.default.Client(this.config);
    await client.connect();
    await client.query(`
      CREATE TABLE IF NOT EXISTS tecto_keys (
        id TEXT PRIMARY KEY, secret BYTEA NOT NULL,
        is_current BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    const res = await client.query(
      "SELECT id, secret, is_current FROM tecto_keys ORDER BY created_at ASC",
    );
    for (const row of res.rows as Array<{ id: string; secret: Buffer; is_current: boolean }>) {
      const key = new Uint8Array(row.secret);
      this.mem.addKey(row.id, key);
      if (row.is_current) {
        this.mem.rotate(row.id, key);
      }
    }
    await client.end();
  }

  async addKey(id: string, secret: Uint8Array): Promise<void> {
    assertEntropy(secret);
    this.mem.addKey(id, secret);
    const pg = await import("pg");
    const client = new pg.default.Client(this.config);
    await client.connect();
    const cur = this.mem.getCurrentKeyId() === id;
    await client.query("INSERT INTO tecto_keys (id, secret, is_current) VALUES ($1, $2, $3)", [
      id,
      Buffer.from(secret),
      cur,
    ]);
    await client.end();
  }

  async rotate(newId: string, newSecret: Uint8Array): Promise<void> {
    assertEntropy(newSecret);
    const pg = await import("pg");
    const client = new pg.default.Client(this.config);
    await client.connect();
    try {
      await client.query("BEGIN");
      await client.query("UPDATE tecto_keys SET is_current = FALSE");
      await client.query("INSERT INTO tecto_keys (id, secret, is_current) VALUES ($1, $2, TRUE)", [
        newId,
        Buffer.from(newSecret),
      ]);
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    }
    this.mem.rotate(newId, newSecret);
    await client.end();
  }

  async removeKey(id: string): Promise<void> {
    this.mem.removeKey(id);
    const pg = await import("pg");
    const client = new pg.default.Client(this.config);
    await client.connect();
    await client.query("DELETE FROM tecto_keys WHERE id = $1", [id]);
    await client.end();
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
  port: Number.parseInt(process.env.DB_PORT ?? "5432", 10),
  user: process.env.DB_USER ?? "postgres",
  password: process.env.DB_PASSWORD ?? "",
  database: process.env.DB_NAME ?? "tecto_example",
};

console.log("╔══════════════════════════════════════════════════════╗");
console.log("║    TECTO — PostgreSQL KeyStoreAdapter Example       ║");
console.log("╚══════════════════════════════════════════════════════╝\n");

try {
  const store = new PostgresKeyStore(config);
  await store.initialize();
  await store.addKey("key-v1", generateSecureKey());
  await store.rotate("key-v2", generateSecureKey());

  const coder = new TectoCoder(store);
  const token = coder.encrypt({ userId: 1 }, { expiresIn: "7d" });
  console.log("  Token:", `${token.slice(0, 60)}...\n`);
  console.log("  Decrypted:", JSON.stringify(coder.decrypt(token), null, 2), "\n");

  const fresh = new PostgresKeyStore(config);
  await fresh.initialize();
  const r = new TectoCoder(fresh).decrypt<{ userId: number }>(token);
  console.log("  ✅ After restart:", r.userId, "\n");
} catch (err) {
  if ((err as NodeJS.ErrnoException).code === "ECONNREFUSED") {
    console.log("  ⚠️  PostgreSQL not running. Start with Docker:\n");
    console.log("    docker run -d -p 5432:5432 -e POSTGRES_HOST_AUTH_METHOD=trust \\");
    console.log("      -e POSTGRES_DB=tecto_example postgres:latest\n");
  } else {
    throw err;
  }
}

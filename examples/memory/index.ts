/**
 * TECTO — Memory Key Store Example
 *
 * Uses the built-in `MemoryKeyStore` which implements `KeyStoreAdapter`.
 * Keys live in-process memory and are lost on restart.
 *
 * Run: bun run examples/memory/index.ts
 */

import {
  generateSecureKey,
  InvalidSignatureError,
  MemoryKeyStore,
  TectoCoder,
} from "../../src/index.js";

console.log("╔══════════════════════════════════════════════════════╗");
console.log("║         TECTO — Memory Key Store Example            ║");
console.log("╚══════════════════════════════════════════════════════╝\n");

const store = new MemoryKeyStore();
store.addKey("mem-key-001", generateSecureKey());

const coder = new TectoCoder(store);

const token = coder.encrypt({ userId: 42, role: "admin" }, { expiresIn: "1h", issuer: "my-app" });

console.log("─── Encrypted Token ───\n");
console.log(`  ${token}\n`);
console.log("  ↑ Fully opaque — decoder websites see only noise.\n");

console.log("─── Decrypted Payload ───\n");
console.log(" ", JSON.stringify(coder.decrypt(token), null, 2), "\n");

console.log("─── Tamper Attempt ───\n");
const chars = token.split("");
const idx = token.lastIndexOf(".") + 6;
chars[idx] = chars[idx] === "A" ? "B" : "A";

try {
  coder.decrypt(chars.join(""));
} catch (error) {
  if (error instanceof InvalidSignatureError) {
    console.log("  ✅ Tampered token rejected:", error.message, "\n");
  }
}

console.log("  ⚠️  Memory keys are lost on restart.");
console.log("  See the sqlite/mariadb/postgres examples for persistence.\n");

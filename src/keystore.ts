/**
 * TECTO In-Memory Key Store
 *
 * Manages cryptographic keys for the TECTO protocol. Keys are stored
 * exclusively as `Uint8Array` and are never converted to strings.
 *
 * @security Key material stored as strings can be interned by the
 * JavaScript engine, making it impossible to reliably clear from memory.
 * `Uint8Array` can be zeroed out explicitly when keys are removed.
 *
 * @module
 */

import { KeyError } from "./errors.js";
import { assertEntropy } from "./security.js";
import type { KeyStoreAdapter } from "./types.js";

/**
 * An in-memory key store that supports key rotation and explicit revocation.
 *
 * @security
 * - Keys are stored as `Uint8Array` (never strings) to avoid JS engine internalization.
 * - On `removeKey()`, the key buffer is zeroed before deletion.
 * - `rotate()` adds a new key without removing old ones, so existing tokens
 *   encrypted under previous keys remain decryptable during the rotation window.
 *
 * @example
 * ```ts
 * const store = new MemoryKeyStore();
 * store.addKey("key-2024-01", generateSecureKey());
 * const key = store.getKey("key-2024-01");
 * ```
 */
export class MemoryKeyStore implements KeyStoreAdapter {
  private readonly keys: Map<string, Uint8Array> = new Map();
  private currentKeyId: string | null = null;

  /**
   * Adds a key to the store. If this is the first key, it becomes the current key.
   *
   * @param id - A unique identifier for the key (e.g., `"key-2024-01"`).
   * @param secret - A 32-byte `Uint8Array` key. Validated for entropy.
   * @throws {KeyError} If `secret` is not exactly 32 bytes or has insufficient entropy.
   *
   * @security The secret is cloned internally to prevent external mutation.
   * The original array can be safely zeroed after calling this method.
   */
  addKey(id: string, secret: Uint8Array): void {
    assertEntropy(secret);

    const cloned = new Uint8Array(secret.byteLength);
    cloned.set(secret);
    this.keys.set(id, cloned);

    if (this.currentKeyId === null) {
      this.currentKeyId = id;
    }
  }

  /**
   * Retrieves a key by its identifier.
   *
   * @param id - The key identifier to look up.
   * @returns The key as a `Uint8Array`.
   * @throws {KeyError} If no key exists with the given identifier.
   *
   * @security Returns a reference to the internal buffer. Do NOT
   * modify or zero the returned array — use `removeKey()` for revocation.
   */
  getKey(id: string): Uint8Array {
    const key = this.keys.get(id);
    if (!key) {
      throw new KeyError(`Key not found: "${id}"`);
    }
    return key;
  }

  /**
   * Rotates to a new key. The new key becomes the current key used for
   * encryption. Old keys are retained for decrypting existing tokens.
   *
   * @param newId - Identifier for the new key.
   * @param newSecret - A 32-byte `Uint8Array` key.
   * @throws {KeyError} If `newSecret` fails entropy validation.
   *
   * @security Old keys are intentionally kept so that tokens encrypted
   * under previous keys can still be decrypted. Call `removeKey()` to
   * explicitly revoke an old key when all tokens using it have expired.
   */
  rotate(newId: string, newSecret: Uint8Array): void {
    this.addKey(newId, newSecret);
    this.currentKeyId = newId;
  }

  /**
   * Removes a key from the store and zeros its memory.
   *
   * @param id - The key identifier to remove.
   * @throws {KeyError} If no key exists with the given identifier.
   * @throws {KeyError} If attempting to remove the current active key.
   *
   * @security The key buffer is filled with zeros before being deleted
   * from the map. This is a best-effort measure — the garbage collector
   * may have already copied the buffer. For maximum security, rotate
   * keys frequently and keep rotation windows short.
   */
  removeKey(id: string): void {
    const key = this.keys.get(id);
    if (!key) {
      throw new KeyError(`Key not found: "${id}"`);
    }
    if (this.currentKeyId === id) {
      throw new KeyError("Cannot remove the current active key. Rotate to a new key first.");
    }
    key.fill(0);
    this.keys.delete(id);
  }

  /**
   * Returns the identifier of the current active key used for encryption.
   *
   * @returns The current key identifier.
   * @throws {KeyError} If no keys have been added to the store.
   */
  getCurrentKeyId(): string {
    if (this.currentKeyId === null) {
      throw new KeyError("No keys in the store. Add a key with addKey() first.");
    }
    return this.currentKeyId;
  }

  /**
   * Returns the total number of keys currently in the store.
   */
  get size(): number {
    return this.keys.size;
  }
}

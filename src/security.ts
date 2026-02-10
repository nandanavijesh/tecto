/**
 * TECTO Security Utilities
 *
 * Low-level cryptographic helpers for key generation, constant-time
 * comparison, and entropy validation. These are the foundation of
 * the entire security model.
 *
 * @security Every function in this module is designed to be safe
 * against timing attacks, weak key injection, and other side-channel vectors.
 *
 * @module
 */

import { KeyError } from "./errors.js";

const KEY_LENGTH = 32;
const MIN_UNIQUE_BYTES = 8;

/**
 * Generates a cryptographically secure 32-byte (256-bit) random key
 * suitable for use with XChaCha20-Poly1305.
 *
 * @returns A new `Uint8Array` of 32 cryptographically random bytes.
 *
 * @security Uses the platform's CSPRNG (`crypto.getRandomValues`), which
 * draws from the OS entropy pool. The returned key is never converted
 * to a string to prevent it from being interned by the JavaScript engine
 * or appearing in heap snapshots.
 *
 * @example
 * ```ts
 * const key = generateSecureKey();
 * // key is a Uint8Array of 32 random bytes
 * ```
 */
export function generateSecureKey(): Uint8Array {
  const key = new Uint8Array(KEY_LENGTH);
  crypto.getRandomValues(key);
  return key;
}

/**
 * Performs a constant-time comparison of two byte arrays.
 *
 * @param a - First byte array.
 * @param b - Second byte array.
 * @returns `true` if both arrays are identical, `false` otherwise.
 *
 * @security This function MUST be used instead of `===` or `Buffer.equals()`
 * when comparing secrets, MACs, or key material. A naive comparison
 * short-circuits on the first differing byte, leaking the position of
 * the mismatch via timing. This implementation XORs all bytes and
 * accumulates differences, ensuring the execution time is constant
 * regardless of where (or whether) the arrays differ.
 *
 * @example
 * ```ts
 * const isValid = constantTimeCompare(receivedMac, computedMac);
 * ```
 */
export function constantTimeCompare(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }

  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }

  return diff === 0;
}

/**
 * Validates that a key meets minimum entropy requirements for
 * use with TECTO's XChaCha20-Poly1305 cipher.
 *
 * @param key - The key material to validate.
 * @throws {KeyError} If the key is not exactly 32 bytes, is all zeros,
 *   is a repeating single byte, or has fewer than 8 unique byte values.
 *
 * @security This function prevents common mistakes:
 * - **All-zeros key:** Equivalent to no encryption at all.
 * - **Repeating byte:** Patterns like `0xAA` repeated 32 times are trivially guessable.
 * - **Low diversity:** Keys with fewer than 8 unique byte values lack
 *   sufficient entropy for 256-bit security.
 * - **Wrong length:** XChaCha20-Poly1305 requires exactly 32 bytes.
 *
 * This is a heuristic check, not a formal entropy measurement. For
 * production use, always generate keys with {@link generateSecureKey}.
 *
 * @example
 * ```ts
 * assertEntropy(myKey); // throws KeyError if key is weak
 * ```
 */
export function assertEntropy(key: Uint8Array): void {
  if (!(key instanceof Uint8Array)) {
    throw new KeyError(
      "Key must be a Uint8Array. String keys are forbidden to prevent internalization attacks.",
    );
  }

  if (key.byteLength !== KEY_LENGTH) {
    throw new KeyError(
      `Key must be exactly ${KEY_LENGTH} bytes (${KEY_LENGTH * 8}-bit). Received ${key.byteLength} bytes.`,
    );
  }

  let isAllZeros = true;
  for (let i = 0; i < key.byteLength; i++) {
    if ((key[i] ?? 0) !== 0) {
      isAllZeros = false;
      break;
    }
  }
  if (isAllZeros) {
    throw new KeyError(
      "Key must not be all zeros. Use generateSecureKey() for safe key generation.",
    );
  }

  const firstByte = key[0] ?? 0;
  let isRepeating = true;
  for (let i = 1; i < key.byteLength; i++) {
    if ((key[i] ?? 0) !== firstByte) {
      isRepeating = false;
      break;
    }
  }
  if (isRepeating) {
    throw new KeyError(
      "Key must not be a repeating single byte. Use generateSecureKey() for safe key generation.",
    );
  }

  const uniqueBytes = new Set<number>();
  for (let i = 0; i < key.byteLength; i++) {
    uniqueBytes.add(key[i] ?? 0);
  }
  if (uniqueBytes.size < MIN_UNIQUE_BYTES) {
    throw new KeyError(
      `Key has insufficient entropy: only ${uniqueBytes.size} unique byte values. ` +
        `A minimum of ${MIN_UNIQUE_BYTES} is required. Use generateSecureKey() for safe key generation.`,
    );
  }
}

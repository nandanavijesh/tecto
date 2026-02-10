/**
 * TECTO Type Definitions
 *
 * Strict type definitions for token payloads and signing options.
 * All types are designed to enforce correctness at compile time.
 *
 * @module
 */

/**
 * Standard registered claims for a TECTO token.
 *
 * @security All time-based claims (`exp`, `nbf`, `iat`) are stored as
 * Unix timestamps (seconds since epoch) to avoid timezone ambiguities
 * that could lead to premature or delayed expiration.
 */
export interface TectoRegisteredClaims {
  /** Expiration time (Unix timestamp in seconds). */
  readonly exp?: number;
  /** Not-before time (Unix timestamp in seconds). */
  readonly nbf?: number;
  /** Issued-at time (Unix timestamp in seconds). */
  readonly iat?: number;
  /** Unique token identifier for replay protection. */
  readonly jti?: string;
  /** Issuer identifier. */
  readonly iss?: string;
  /** Audience identifier. */
  readonly aud?: string;
}

/**
 * Complete TECTO token payload including registered claims
 * and user-defined custom fields.
 *
 * @typeParam T - User-defined payload fields. Must be a plain object type.
 *
 * @security Custom fields are encrypted alongside registered claims,
 * ensuring all data is opaque without the secret key.
 */
export type TectoPayload<T extends Record<string, unknown> = Record<string, unknown>> =
  TectoRegisteredClaims & T;

/**
 * Options for token encryption (signing).
 *
 * @security The `expiresIn` field accepts human-readable duration strings
 * (e.g., `"1h"`, `"30m"`, `"7d"`) and is converted to an absolute `exp`
 * claim internally. Always prefer short-lived tokens.
 */
export interface SignOptions {
  /**
   * Token lifetime as a duration string.
   * Supported units: `s` (seconds), `m` (minutes), `h` (hours), `d` (days).
   *
   * @example "1h" — expires in 1 hour
   * @example "30m" — expires in 30 minutes
   * @example "7d" — expires in 7 days
   */
  readonly expiresIn?: string;

  /** Issuer claim (`iss`). */
  readonly issuer?: string;

  /** Audience claim (`aud`). */
  readonly audience?: string;

  /** Unique token ID (`jti`). If omitted, one is generated automatically. */
  readonly jti?: string;

  /**
   * Not-before delay as a duration string.
   * The token will not be valid until this duration has elapsed from `iat`.
   *
   * @example "5m" — token becomes active 5 minutes after issuance
   */
  readonly notBefore?: string;
}

/**
 * Internal representation of a fully resolved TECTO token header.
 * This is never exposed externally.
 */
export interface TectoHeader {
  readonly version: "v1";
  readonly kid: string;
}

/**
 * The contract that all key store implementations must satisfy.
 *
 * Implementations include `MemoryKeyStore` (built-in), `SqliteKeyStore`,
 * `MariaDbKeyStore`, and `PostgresKeyStore`.
 *
 * @security All implementations MUST:
 * - Store keys as `Uint8Array` (never strings) to prevent JS engine internalization.
 * - Validate key entropy via `assertEntropy()` before storing.
 * - Clone key material on ingestion to prevent external mutation.
 */
export interface KeyStoreAdapter {
  /**
   * Adds a key to the store. If this is the first key, it becomes the current key.
   *
   * @param id - A unique identifier for the key (e.g., `"key-2024-01"`).
   * @param secret - A 32-byte `Uint8Array` key. Must pass entropy validation.
   * @throws {KeyError} If `secret` is not exactly 32 bytes or has insufficient entropy.
   */
  addKey(id: string, secret: Uint8Array): void | Promise<void>;

  /**
   * Retrieves a key by its identifier.
   *
   * @param id - The key identifier to look up.
   * @returns The key as a `Uint8Array`.
   * @throws {KeyError} If no key exists with the given identifier.
   */
  getKey(id: string): Uint8Array;

  /**
   * Rotates to a new key. The new key becomes the current key used for
   * encryption. Old keys MUST be retained for decrypting existing tokens.
   *
   * @param newId - Identifier for the new key.
   * @param newSecret - A 32-byte `Uint8Array` key.
   * @throws {KeyError} If `newSecret` fails entropy validation.
   */
  rotate(newId: string, newSecret: Uint8Array): void | Promise<void>;

  /**
   * Removes a key from the store.
   *
   * @param id - The key identifier to remove.
   * @throws {KeyError} If no key exists or if attempting to remove the current key.
   */
  removeKey(id: string): void | Promise<void>;

  /**
   * Returns the identifier of the current active key used for encryption.
   *
   * @throws {KeyError} If no keys have been added to the store.
   */
  getCurrentKeyId(): string;

  /** Returns the total number of keys in the store. */
  readonly size: number;
}

/**
 * TECTO SDK — Public API
 *
 * Re-exports all public types, classes, and functions for the TECTO
 * (Transport Encrypted Compact Token Object) protocol.
 *
 * @packageDocumentation
 */

export { TectoCoder } from "./core.js";
export {
  InvalidSignatureError,
  KeyError,
  TectoError,
  TokenExpiredError,
  TokenNotActiveError,
} from "./errors.js";
export { MemoryKeyStore } from "./keystore.js";
export { assertEntropy, constantTimeCompare, generateSecureKey } from "./security.js";
export type { KeyStoreAdapter, SignOptions, TectoPayload, TectoRegisteredClaims } from "./types.js";

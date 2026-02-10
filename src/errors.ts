/**
 * TECTO Error Hierarchy
 *
 * All errors extend the base `TectoError` class. Error messages are
 * intentionally generic where security-sensitive to prevent oracle attacks.
 *
 * @security Generic error messages prevent attackers from distinguishing
 * between padding failures, authentication failures, and other decryption
 * errors — eliminating side-channel information leakage.
 *
 * @module
 */

/**
 * Base error class for all TECTO-related errors.
 *
 * @security Consumers should catch `TectoError` as the top-level type
 * and avoid exposing internal error details to end users.
 */
export class TectoError extends Error {
  public readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = "TectoError";
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when a token's `exp` claim is in the past.
 *
 * @security This is safe to throw distinctly from `InvalidSignatureError`
 * because expiration is checked *after* successful decryption and
 * authentication, so no ciphertext oracle is possible.
 */
export class TokenExpiredError extends TectoError {
  public readonly expiredAt: Date;

  constructor(expiredAt: Date) {
    super("Token has expired", "TECTO_TOKEN_EXPIRED");
    this.name = "TokenExpiredError";
    this.expiredAt = expiredAt;
  }
}

/**
 * Thrown when decryption or authentication fails for any reason.
 *
 * @security This error intentionally uses a single generic message for ALL
 * decryption failures — whether the key is wrong, the ciphertext is tampered,
 * the nonce is invalid, or the Poly1305 tag doesn't match. Revealing the
 * specific failure mode would create a padding/authentication oracle.
 */
export class InvalidSignatureError extends TectoError {
  constructor() {
    super("Invalid token", "TECTO_INVALID_TOKEN");
    this.name = "InvalidSignatureError";
  }
}

/**
 * Thrown when a cryptographic key fails validation.
 *
 * @security Key-related errors are safe to be descriptive because they
 * occur during setup/configuration, not during token verification flows
 * that an attacker could probe.
 */
export class KeyError extends TectoError {
  constructor(message: string) {
    super(message, "TECTO_KEY_ERROR");
    this.name = "KeyError";
  }
}

/**
 * Thrown when a token's `nbf` (not before) claim is in the future.
 *
 * @security Like `TokenExpiredError`, this is checked after successful
 * decryption so it does not leak ciphertext information.
 */
export class TokenNotActiveError extends TectoError {
  public readonly activeAt: Date;

  constructor(activeAt: Date) {
    super("Token is not yet active", "TECTO_TOKEN_NOT_ACTIVE");
    this.name = "TokenNotActiveError";
    this.activeAt = activeAt;
  }
}

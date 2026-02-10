import { describe, expect, test } from "bun:test";
import {
  assertEntropy,
  constantTimeCompare,
  generateSecureKey,
  InvalidSignatureError,
  KeyError,
  MemoryKeyStore,
  TectoCoder,
  TokenExpiredError,
  TokenNotActiveError,
} from "../src/index";

describe("Security Utilities", () => {
  test("generateSecureKey produces 32 random bytes", () => {
    const key = generateSecureKey();
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.byteLength).toBe(32);
  });

  test("generateSecureKey produces unique keys", () => {
    const a = generateSecureKey();
    const b = generateSecureKey();
    expect(constantTimeCompare(a, b)).toBe(false);
  });

  test("constantTimeCompare returns true for identical arrays", () => {
    const a = new Uint8Array([1, 2, 3, 4]);
    const b = new Uint8Array([1, 2, 3, 4]);
    expect(constantTimeCompare(a, b)).toBe(true);
  });

  test("constantTimeCompare returns false for different arrays", () => {
    const a = new Uint8Array([1, 2, 3, 4]);
    const b = new Uint8Array([1, 2, 3, 5]);
    expect(constantTimeCompare(a, b)).toBe(false);
  });

  test("constantTimeCompare returns false for different lengths", () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3, 4]);
    expect(constantTimeCompare(a, b)).toBe(false);
  });
});

describe("Entropy Validation", () => {
  test("rejects string keys (type enforcement)", () => {
    expect(() => assertEntropy("password123" as unknown as Uint8Array)).toThrow(KeyError);
  });

  test("rejects keys shorter than 32 bytes", () => {
    const short = new Uint8Array(16);
    crypto.getRandomValues(short);
    expect(() => assertEntropy(short)).toThrow(KeyError);
  });

  test("rejects keys longer than 32 bytes", () => {
    const long = new Uint8Array(64);
    crypto.getRandomValues(long);
    expect(() => assertEntropy(long)).toThrow(KeyError);
  });

  test("rejects all-zero keys", () => {
    const zeros = new Uint8Array(32);
    expect(() => assertEntropy(zeros)).toThrow(KeyError);
  });

  test("rejects repeating single-byte keys", () => {
    const repeating = new Uint8Array(32).fill(0xaa);
    expect(() => assertEntropy(repeating)).toThrow(KeyError);
  });

  test("rejects low-entropy keys (few unique bytes)", () => {
    const low = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      low[i] = i % 3;
    }
    expect(() => assertEntropy(low)).toThrow(KeyError);
  });

  test("accepts valid high-entropy keys", () => {
    const key = generateSecureKey();
    expect(() => assertEntropy(key)).not.toThrow();
  });
});

describe("MemoryKeyStore", () => {
  test("stores and retrieves keys", () => {
    const store = new MemoryKeyStore();
    const key = generateSecureKey();
    store.addKey("k1", key);
    const retrieved = store.getKey("k1");
    expect(constantTimeCompare(key, retrieved)).toBe(true);
  });

  test("clones key on addKey (mutation safety)", () => {
    const store = new MemoryKeyStore();
    const key = generateSecureKey();
    const original = new Uint8Array(key);
    store.addKey("k1", key);
    key.fill(0);
    const retrieved = store.getKey("k1");
    expect(constantTimeCompare(original, retrieved)).toBe(true);
  });

  test("throws KeyError for unknown key ID", () => {
    const store = new MemoryKeyStore();
    expect(() => store.getKey("nonexistent")).toThrow(KeyError);
  });

  test("rotate sets new current key", () => {
    const store = new MemoryKeyStore();
    store.addKey("k1", generateSecureKey());
    expect(store.getCurrentKeyId()).toBe("k1");

    store.rotate("k2", generateSecureKey());
    expect(store.getCurrentKeyId()).toBe("k2");
    expect(store.size).toBe(2);
  });

  test("removeKey zeros and deletes the key", () => {
    const store = new MemoryKeyStore();
    store.addKey("k1", generateSecureKey());
    store.rotate("k2", generateSecureKey());
    store.removeKey("k1");
    expect(store.size).toBe(1);
    expect(() => store.getKey("k1")).toThrow(KeyError);
  });

  test("cannot remove current active key", () => {
    const store = new MemoryKeyStore();
    store.addKey("k1", generateSecureKey());
    expect(() => store.removeKey("k1")).toThrow(KeyError);
  });

  test("getCurrentKeyId throws when store is empty", () => {
    const store = new MemoryKeyStore();
    expect(() => store.getCurrentKeyId()).toThrow(KeyError);
  });
});

describe("TectoCoder — Encryption & Decryption", () => {
  function createCoder(): TectoCoder {
    const store = new MemoryKeyStore();
    store.addKey("test-key", generateSecureKey());
    return new TectoCoder(store);
  }

  test("encrypts and decrypts a payload", () => {
    const coder = createCoder();
    const token = coder.encrypt({ userId: 42, role: "admin" }, { expiresIn: "1h" });
    const payload = coder.decrypt<{ userId: number; role: string }>(token);

    expect(payload.userId).toBe(42);
    expect(payload.role).toBe("admin");
    expect(payload.iat).toBeNumber();
    expect(payload.exp).toBeNumber();
    expect(payload.jti).toBeString();
  });

  test("token has correct tecto.v1 prefix", () => {
    const coder = createCoder();
    const token = coder.encrypt({ data: "test" }, { expiresIn: "1h" });
    expect(token.startsWith("tecto.v1.")).toBe(true);
  });

  test("token has exactly 5 segments", () => {
    const coder = createCoder();
    const token = coder.encrypt({ data: "test" }, { expiresIn: "1h" });
    expect(token.split(".").length).toBe(5);
  });

  test("each encryption produces unique tokens (unique nonce)", () => {
    const coder = createCoder();
    const payload = { data: "same" };
    const opts = { expiresIn: "1h" };
    const token1 = coder.encrypt(payload, opts);
    const token2 = coder.encrypt(payload, opts);
    expect(token1).not.toBe(token2);
  });

  test("sets iss and aud claims", () => {
    const coder = createCoder();
    const token = coder.encrypt(
      { msg: "hello" },
      { expiresIn: "1h", issuer: "my-issuer", audience: "my-audience" },
    );
    const payload = coder.decrypt<{ msg: string }>(token);
    expect(payload.iss).toBe("my-issuer");
    expect(payload.aud).toBe("my-audience");
  });

  test("respects custom jti", () => {
    const coder = createCoder();
    const token = coder.encrypt({ x: 1 }, { expiresIn: "1h", jti: "custom-id-123" });
    const payload = coder.decrypt<{ x: number }>(token);
    expect(payload.jti).toBe("custom-id-123");
  });
});

describe("TectoCoder — Tamper Resistance", () => {
  function createCoder(): TectoCoder {
    const store = new MemoryKeyStore();
    store.addKey("test-key", generateSecureKey());
    return new TectoCoder(store);
  }

  test("flipping a bit in ciphertext causes decryption failure", () => {
    const coder = createCoder();
    const token = coder.encrypt({ secret: "data" }, { expiresIn: "1h" });

    const segments = token.split(".");
    const ciphertext = segments[4]!;
    const chars = ciphertext.split("");
    chars[5] = chars[5] === "A" ? "B" : "A";
    segments[4] = chars.join("");
    const tampered = segments.join(".");

    expect(() => coder.decrypt(tampered)).toThrow(InvalidSignatureError);
  });

  test("flipping a bit in nonce causes decryption failure", () => {
    const coder = createCoder();
    const token = coder.encrypt({ secret: "data" }, { expiresIn: "1h" });

    const segments = token.split(".");
    const nonce = segments[3]!;
    const chars = nonce.split("");
    chars[2] = chars[2] === "A" ? "B" : "A";
    segments[3] = chars.join("");
    const tampered = segments.join(".");

    expect(() => coder.decrypt(tampered)).toThrow(InvalidSignatureError);
  });

  test("wrong key ID causes generic InvalidSignatureError", () => {
    const coder = createCoder();
    const token = coder.encrypt({ x: 1 }, { expiresIn: "1h" });
    const tampered = token.replace("test-key", "wrong-key");
    expect(() => coder.decrypt(tampered)).toThrow(InvalidSignatureError);
  });

  test("completely garbled token throws InvalidSignatureError", () => {
    const coder = createCoder();
    expect(() => coder.decrypt("not.a.valid.token.at-all")).toThrow(InvalidSignatureError);
  });

  test("empty string throws InvalidSignatureError", () => {
    const coder = createCoder();
    expect(() => coder.decrypt("")).toThrow(InvalidSignatureError);
  });

  test("wrong number of segments throws InvalidSignatureError", () => {
    const coder = createCoder();
    expect(() => coder.decrypt("tecto.v1.kid.nonce")).toThrow(InvalidSignatureError);
  });

  test("wrong prefix throws InvalidSignatureError", () => {
    const coder = createCoder();
    const token = coder.encrypt({ x: 1 }, { expiresIn: "1h" });
    const tampered = token.replace("tecto", "jwt");
    expect(() => coder.decrypt(tampered)).toThrow(InvalidSignatureError);
  });
});

describe("TectoCoder — Time-Based Claims", () => {
  function createCoder(): TectoCoder {
    const store = new MemoryKeyStore();
    store.addKey("test-key", generateSecureKey());
    return new TectoCoder(store);
  }

  test("expired token throws TokenExpiredError", () => {
    const store = new MemoryKeyStore();
    const key = generateSecureKey();
    store.addKey("k1", key);
    const coder = new TectoCoder(store);

    const pastExp = Math.floor(Date.now() / 1000) - 10;
    const token = coder.encrypt({ exp: pastExp } as Record<string, unknown>);

    expect(() => coder.decrypt(token)).toThrow(TokenExpiredError);
  });

  test("nbf in the future throws TokenNotActiveError", () => {
    const coder = createCoder();
    const token = coder.encrypt({}, { expiresIn: "1h", notBefore: "1h" });
    expect(() => coder.decrypt(token)).toThrow(TokenNotActiveError);
  });

  test("valid nbf in the past does not throw", () => {
    const store = new MemoryKeyStore();
    const key = generateSecureKey();
    store.addKey("k1", key);
    const coder = new TectoCoder(store);

    const pastNbf = Math.floor(Date.now() / 1000) - 60;
    const futureExp = Math.floor(Date.now() / 1000) + 3600;
    const token = coder.encrypt({
      nbf: pastNbf,
      exp: futureExp,
    } as Record<string, unknown>);

    expect(() => coder.decrypt(token)).not.toThrow();
  });
});

describe("TectoCoder — Key Rotation", () => {
  test("tokens encrypted with old key are still decryptable after rotation", () => {
    const store = new MemoryKeyStore();
    store.addKey("key-v1", generateSecureKey());
    const coder = new TectoCoder(store);

    const tokenV1 = coder.encrypt({ version: 1 }, { expiresIn: "1h" });

    store.rotate("key-v2", generateSecureKey());

    const tokenV2 = coder.encrypt({ version: 2 }, { expiresIn: "1h" });

    const payloadV1 = coder.decrypt<{ version: number }>(tokenV1);
    const payloadV2 = coder.decrypt<{ version: number }>(tokenV2);

    expect(payloadV1.version).toBe(1);
    expect(payloadV2.version).toBe(2);
  });

  test("new tokens use the rotated key", () => {
    const store = new MemoryKeyStore();
    store.addKey("key-v1", generateSecureKey());
    store.rotate("key-v2", generateSecureKey());
    const coder = new TectoCoder(store);

    const token = coder.encrypt({ x: 1 }, { expiresIn: "1h" });
    expect(token).toContain("key-v2");
  });
});

describe("TectoCoder — Cross-Key Isolation", () => {
  test("token from one key cannot be decrypted with another", () => {
    const store1 = new MemoryKeyStore();
    store1.addKey("k1", generateSecureKey());
    const coder1 = new TectoCoder(store1);

    const store2 = new MemoryKeyStore();
    store2.addKey("k1", generateSecureKey());
    const coder2 = new TectoCoder(store2);

    const token = coder1.encrypt({ secret: "only-for-coder1" }, { expiresIn: "1h" });
    expect(() => coder2.decrypt(token)).toThrow(InvalidSignatureError);
  });
});

describe("TectoCoder — JTI Parsing", () => {
  test("auto-generated jti is present and is a hex string", () => {
    const coder = createCoderHelper();
    const token = coder.encrypt({ data: "test" }, { expiresIn: "1h" });
    const payload = coder.decrypt(token);
    expect(payload.jti).toBeString();
    expect(payload.jti!.length).toBe(32);
    expect(/^[0-9a-f]{32}$/.test(payload.jti!)).toBe(true);
  });

  test("custom jti is preserved", () => {
    const coder = createCoderHelper();
    const token = coder.encrypt({ data: "test" }, { expiresIn: "1h", jti: "my-unique-id" });
    const payload = coder.decrypt(token);
    expect(payload.jti).toBe("my-unique-id");
  });
});

function createCoderHelper(): TectoCoder {
  const store = new MemoryKeyStore();
  store.addKey("test-key", generateSecureKey());
  return new TectoCoder(store);
}

/**
 * The key-holder contract (docs/CIPA_PHASE5_KEY_HOLDER_PLAN.md §4; CONTRACT.md is the prose form).
 *
 * Three operations — GET /public-key, POST /unwrap, GET /health — with more than one implementation
 * behind them: the Cloudflare Worker in this package (which a publisher runs in their own account) and
 * AWS KMS reached through per-purpose roles (worker/src/keyholder/kmsHolderClient.ts). This module is
 * everything both sides must agree on: the purposes, the wrapped payload, the key identifier, the
 * outcome vocabulary and the mapping from what a holder answers to what SafeBind's caller sees. It has
 * no dependencies and no I/O, so the seal worker imports it directly.
 */

export const HOLDER_ALG = "RSA-OAEP-256" as const;

/** Why SafeBind is calling. The credential fixes it; the body must say the same thing. */
export const PURPOSES = ["derive", "qa", "release"] as const;
export type Purpose = (typeof PURPOSES)[number];
export const isPurpose = (value: unknown): value is Purpose =>
  typeof value === "string" && (PURPOSES as readonly string[]).includes(value);

/**
 * What the holder writes in its audit row. `ok` is the only row that released a key. The refusals
 * that name a credential are logged too; `unknown_credential` and `not_initialised` are not, because
 * neither can be attributed to a purpose the log could carry.
 */
export const HOLDER_OUTCOMES = [
  "ok",
  "revoked",
  "unknown_kid",
  "key_destroyed",
  "bad_wrap",
  "cert_mismatch"
] as const;
export type HolderOutcome = (typeof HOLDER_OUTCOMES)[number];
export const isHolderOutcome = (value: unknown): value is HolderOutcome =>
  typeof value === "string" && (HOLDER_OUTCOMES as readonly string[]).includes(value);

/**
 * What SafeBind's caller sees. `publisher_revoked` and `publisher_unavailable` are the two the design
 * names (§2.5: 423 and 503 + retry-after); the rest are the holder's own refusals passed through.
 * There is deliberately no "fallback" member.
 */
export type UnwrapState =
  | "publisher_revoked"
  | "publisher_unavailable"
  | "unknown_kid"
  | "key_destroyed"
  | "bad_wrap"
  | "cert_mismatch";

export type UnwrapResult =
  | { ok: true; k1: Uint8Array; kver: number; kid: string; logSeq: string }
  | { ok: false; state: UnwrapState; detail: string };

/** The audit row every implementation must be able to export (the Worker keeps it itself; the KMS
 *  variant's equivalent is CloudTrail, joined on `request_id` = the STS session name's suffix). */
export interface AuditRow {
  seq: number;
  at: string;
  purpose: Purpose;
  cert_id: string;
  kid: string;
  outcome: HolderOutcome;
  request_id: string;
}

export interface PublicKeyAnswer {
  kid: string;
  /** Standard base64 of the SubjectPublicKeyInfo DER. */
  spki: string;
  alg: typeof HOLDER_ALG;
  created_at: string;
  previous_kids: string[];
}

export type KeyState = "active" | "destroyed" | "uninitialised";

export interface HealthAnswer {
  ok: boolean;
  initialised: boolean;
  kid: string | null;
  key_state: KeyState;
}

// ── The wrapped payload ──────────────────────────────────────────────────────────────────────────
// Design §2.2 step 2: RSA-OAEP over K₁ ‖ certId ‖ kver. Exactly 52 bytes: K₁ (32) ‖ the certificate's
// 16 raw UUID bytes ‖ kver as a big-endian uint32. The holder (or, for KMS, SafeBind's client after the
// decrypt) checks the certificate inside the wrap against the one the caller named, so an audit row can
// never describe a different certificate than the one that was opened.

export const K1_BYTES = 32;
export const PAYLOAD_BYTES = K1_BYTES + 16 + 4;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const isUuid = (value: unknown): value is string =>
  typeof value === "string" && UUID_RE.test(value);

export function uuidToBytes(uuid: string): Uint8Array {
  if (!isUuid(uuid)) throw new Error("not a UUID");
  const hex = uuid.replace(/-/g, "");
  const bytes = new Uint8Array(16);
  for (let index = 0; index < 16; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

export function bytesToUuid(bytes: Uint8Array): string {
  if (bytes.length !== 16) throw new Error("a UUID is 16 bytes");
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function encodeWrappedPayload(k1: Uint8Array, certId: string, kver: number): Uint8Array {
  if (k1.length !== K1_BYTES) throw new Error(`K1 must be ${K1_BYTES} bytes`);
  if (!Number.isInteger(kver) || kver < 0 || kver > 0xffffffff)
    throw new Error("kver must be a uint32");
  const payload = new Uint8Array(PAYLOAD_BYTES);
  payload.set(k1, 0);
  payload.set(uuidToBytes(certId), K1_BYTES);
  new DataView(payload.buffer).setUint32(K1_BYTES + 16, kver, false);
  return payload;
}

export type ParsedPayload =
  | { ok: true; k1: Uint8Array; kver: number; certId: string }
  | { ok: false; reason: "bad_wrap" | "cert_mismatch"; detail: string };

/** The one place the decrypted bytes are read. `expectedCertId` is what the caller named. */
export function parseWrappedPayload(bytes: Uint8Array, expectedCertId: string): ParsedPayload {
  if (bytes.length !== PAYLOAD_BYTES) {
    return {
      ok: false,
      reason: "bad_wrap",
      detail: `payload is ${bytes.length} bytes, expected ${PAYLOAD_BYTES}`
    };
  }
  const certId = bytesToUuid(bytes.slice(K1_BYTES, K1_BYTES + 16));
  if (certId.toLowerCase() !== expectedCertId.toLowerCase()) {
    return { ok: false, reason: "cert_mismatch", detail: "the wrap names a different certificate" };
  }
  const kver = new DataView(bytes.buffer, bytes.byteOffset).getUint32(K1_BYTES + 16, false);
  return { ok: true, k1: bytes.slice(0, K1_BYTES), kver, certId };
}

// ── Key identity ─────────────────────────────────────────────────────────────────────────────────
// kid = base64url of the first 16 bytes of SHA-256(SPKI DER). Derived, never assigned, so every
// implementation and SafeBind compute the same identifier from the same key.

export async function kidOf(spki: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", spki));
  return base64UrlEncode(digest.slice(0, 16));
}

/** The smallest RSA modulus the contract accepts; the Worker mints 2048. */
export const MIN_MODULUS_BITS = 2048;

/**
 * A served SPKI is a usable holder key only if it imports as RSA-OAEP-256 for encryption with an
 * acceptable modulus — a matching kid over arbitrary bytes proves nothing (plan §7.2: "its SPKI
 * imports as RSA-OAEP-256"). Null when it does not.
 */
export async function importHolderPublicKey(spki: Uint8Array): Promise<CryptoKey | null> {
  try {
    const key = await crypto.subtle.importKey(
      "spki",
      spki,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["encrypt"]
    );
    const { algorithm } = key;
    return "modulusLength" in algorithm &&
      typeof algorithm.modulusLength === "number" &&
      algorithm.modulusLength >= MIN_MODULUS_BITS
      ? key
      : null;
  } catch {
    return null;
  }
}

// ── Encodings ────────────────────────────────────────────────────────────────────────────────────

export function base64Encode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function base64Decode(text: string): Uint8Array {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

export function base64UrlEncode(bytes: Uint8Array): string {
  return base64Encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Base64 that tolerates a malformed string by returning null instead of throwing. */
export function tryBase64Decode(text: unknown): Uint8Array | null {
  if (typeof text !== "string" || text.length === 0) return null;
  try {
    return base64Decode(text);
  } catch {
    return null;
  }
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

// ── The shared state mapping (plan §4) ───────────────────────────────────────────────────────────
// What a Worker holder answers over HTTP → what SafeBind's caller sees. The KMS client maps its own
// exceptions onto the same UnwrapState values (kmsHolderClient.ts), so the two cannot drift.

export interface HolderHttpAnswer {
  status: number;
  /** The `error` field of the body, when the body was JSON with one. */
  error: string | null;
}

export function stateForHolderAnswer(answer: HolderHttpAnswer): UnwrapState {
  if (answer.status === 403 && answer.error === "revoked") return "publisher_revoked";
  if (answer.status === 404 && answer.error === "unknown_kid") return "unknown_kid";
  if (answer.status === 410) return "key_destroyed";
  if (answer.status === 400 && answer.error === "cert_mismatch") return "cert_mismatch";
  if (answer.status === 400 && answer.error === "bad_wrap") return "bad_wrap";
  // 401 (a credential the holder does not know), 503 not_initialised, 5xx, 429 and anything unexpected:
  // the holder did not answer the question, and only an authoritative answer may move state further.
  return "publisher_unavailable";
}

/** Whether a state is authoritative evidence that the key is gone (plan §4 table, last column). */
export const isAuthoritativeGone = (state: UnwrapState): boolean => state === "key_destroyed";

/** The purpose-scoped bearer's shape: a prefix naming the purpose, then 32 random bytes, base64url. */
export const CREDENTIAL_PREFIX = {
  derive: "khd_",
  qa: "khq_",
  release: "khr_"
} as const satisfies Record<Purpose, string>;

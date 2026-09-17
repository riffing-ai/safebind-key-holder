/**
 * The holder's operations, independent of HTTP and of the Durable Object runtime (plan §5).
 *
 * Everything that changes key or credential state — init, rotate, destroy, revoke, reissue — runs
 * inside `runtime.serialise` (the object's `blockConcurrencyWhile`) AND commits in one synchronous
 * transaction that re-reads what it depends on (the initialised marker, the current kid) and refuses
 * if it changed. Unwrap is not serialised: it reads, decrypts, appends its audit row and answers, and
 * the append is the last thing before the answer — no audit row, no key.
 */

import {
  CREDENTIAL_PREFIX,
  type AuditRow,
  type HolderOutcome,
  type KeyState,
  type Purpose,
  PURPOSES,
  type PublicKeyAnswer,
  base64Decode,
  base64Encode,
  base64UrlEncode,
  isHolderOutcome,
  isPurpose,
  kidOf,
  parseWrappedPayload,
  sha256Hex
} from "./contract";
import { type HolderRuntime, type SqlRow, ensureSchema, readMeta, writeMeta } from "./store";

export interface KeyPairBytes {
  spki: Uint8Array;
  pkcs8: Uint8Array;
}

/** The two things the core needs from the platform, injectable so a test can hold key generation open. */
export interface HolderDeps {
  generateKeyPair(): Promise<KeyPairBytes>;
  randomBytes(length: number): Uint8Array;
}

export const webCryptoDeps: HolderDeps = {
  async generateKeyPair() {
    const generated = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
      },
      true,
      ["encrypt", "decrypt"]
    );
    if (!("privateKey" in generated))
      throw new Error("RSA-OAEP generateKey did not return a key pair");
    const spki = await crypto.subtle.exportKey("spki", generated.publicKey);
    const pkcs8 = await crypto.subtle.exportKey("pkcs8", generated.privateKey);
    // workers-types type exportKey as ArrayBuffer | JsonWebKey for every format; "spki"/"pkcs8" are DER.
    if (!(spki instanceof ArrayBuffer) || !(pkcs8 instanceof ArrayBuffer))
      throw new Error("exportKey did not return DER");
    return { spki: new Uint8Array(spki), pkcs8: new Uint8Array(pkcs8) };
  },
  randomBytes: (length) => crypto.getRandomValues(new Uint8Array(length))
};

export type Credentials = Record<Purpose, string>;

export type InitResult =
  | { ok: true; kid: string; credentials: Credentials }
  | { ok: false; error: "already_initialised" };
export type RotateResult =
  | { ok: true; kid: string; previous: string }
  | { ok: false; error: "not_initialised" | "key_destroyed" | "conflict" };
export type DestroyResult =
  | { ok: true; kid: string }
  | {
      ok: false;
      error: "not_initialised" | "key_destroyed" | "confirm_mismatch";
      expected?: string;
    };
export type CredentialResult =
  | { ok: true; purpose: Purpose; credential: string | null }
  | { ok: false; error: "not_initialised" };
export type PublicKeyResult =
  | { ok: true; key: PublicKeyAnswer }
  | { ok: false; error: "not_initialised" | "key_destroyed" | "unknown_kid" };

export interface UnwrapRequest {
  bearer: string;
  kid: string;
  wrap: Uint8Array;
  certId: string;
  purpose: Purpose;
  requestId: string;
}

export type UnwrapRefusal =
  | "not_initialised"
  | "unknown_credential"
  | "purpose_mismatch"
  | "revoked"
  | "unknown_kid"
  | "key_destroyed"
  | "bad_wrap"
  | "cert_mismatch"
  | "audit_failed";

export type HolderUnwrap =
  | { ok: true; k1: Uint8Array; kver: number; kid: string; logSeq: number; purpose: Purpose }
  | { ok: false; error: UnwrapRefusal; purpose: Purpose | null; detail: string };

export interface HealthResult {
  ok: boolean;
  initialised: boolean;
  kid: string | null;
  key_state: KeyState;
}

export interface LogQuery {
  from?: string;
  to?: string;
  /** Rows after this seq (a cursor); the export is paged by 5,000. */
  after?: number;
}
export const LOG_PAGE = 5000;

export interface HolderCore {
  init(): Promise<InitResult>;
  rotate(): Promise<RotateResult>;
  destroy(confirm: string): Promise<DestroyResult>;
  revoke(purpose: Purpose): Promise<CredentialResult>;
  reissue(purpose: Purpose): Promise<CredentialResult>;
  publicKey(kid?: string): PublicKeyResult;
  health(): HealthResult;
  unwrap(request: UnwrapRequest): Promise<HolderUnwrap>;
  exportLog(query: LogQuery): AuditRow[];
}

interface KeyRow {
  kid: string;
  spki: string;
  pkcs8: string;
  created_at: string;
  is_current: number;
}

const isKeyRow = (row: SqlRow | undefined): row is KeyRow & SqlRow =>
  row !== undefined &&
  typeof row.kid === "string" &&
  typeof row.spki === "string" &&
  typeof row.pkcs8 === "string" &&
  typeof row.created_at === "string" &&
  typeof row.is_current === "number";

interface CredentialRow {
  purpose: Purpose;
  revoked_at: string | null;
}

const isCredentialRow = (row: SqlRow | undefined): row is CredentialRow & SqlRow =>
  row !== undefined &&
  isPurpose(row.purpose) &&
  (row.revoked_at === null || typeof row.revoked_at === "string");

const isAuditRow = (row: SqlRow): row is AuditRow & SqlRow =>
  typeof row.seq === "number" &&
  typeof row.at === "string" &&
  isPurpose(row.purpose) &&
  typeof row.cert_id === "string" &&
  typeof row.kid === "string" &&
  isHolderOutcome(row.outcome) &&
  typeof row.request_id === "string";

const textBytes = (text: string): Uint8Array => new TextEncoder().encode(text);

export function createHolderCore(
  runtime: HolderRuntime,
  deps: HolderDeps = webCryptoDeps
): HolderCore {
  const { store } = runtime;
  ensureSchema(store);
  const privateKeys = new Map<string, Promise<CryptoKey>>();

  const initialised = (): boolean => readMeta(store, "initialised") === "1";
  const destroyedAt = (): string | null => readMeta(store, "destroyed_at");
  const currentKey = (): KeyRow | null => {
    const row = store.exec(
      "select kid, spki, pkcs8, created_at, is_current from keys where is_current = 1"
    )[0];
    return isKeyRow(row) ? row : null;
  };
  const keyByKid = (kid: string): KeyRow | null => {
    const row = store.exec(
      "select kid, spki, pkcs8, created_at, is_current from keys where kid = ?",
      kid
    )[0];
    return isKeyRow(row) ? row : null;
  };
  const previousKids = (): string[] =>
    store
      .exec("select kid from keys where is_current = 0 order by created_at desc")
      .map((row) => row.kid)
      .filter((kid): kid is string => typeof kid === "string");

  const mintBearer = (purpose: Purpose): string =>
    `${CREDENTIAL_PREFIX[purpose]}${base64UrlEncode(deps.randomBytes(32))}`;
  const hashBearer = (bearer: string): Promise<string> => sha256Hex(textBytes(bearer));

  const privateKeyFor = (row: KeyRow): Promise<CryptoKey> => {
    const cached = privateKeys.get(row.kid);
    if (cached !== undefined) return cached;
    const imported = crypto.subtle.importKey(
      "pkcs8",
      base64Decode(row.pkcs8),
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["decrypt"]
    );
    privateKeys.set(row.kid, imported);
    return imported;
  };

  /** The audit append. Throws if the store refuses; the caller turns that into `audit_failed`. */
  const appendAudit = (
    purpose: Purpose,
    certId: string,
    kid: string,
    outcome: HolderOutcome,
    requestId: string
  ): number => {
    const row = store.exec(
      "insert into audit (at, purpose, cert_id, kid, outcome, request_id) values (?, ?, ?, ?, ?, ?) returning seq",
      runtime.now(),
      purpose,
      certId,
      kid,
      outcome,
      requestId
    )[0];
    if (typeof row?.seq !== "number") throw new Error("audit append returned no seq");
    return row.seq;
  };

  const refuse = (error: UnwrapRefusal, purpose: Purpose | null, detail: string): HolderUnwrap => ({
    ok: false,
    error,
    purpose,
    detail
  });

  /** A refusal that names a credential is logged before it is answered; a failed log is `audit_failed`. */
  const refuseLogged = (
    outcome: Exclude<HolderOutcome, "ok">,
    request: UnwrapRequest,
    detail: string
  ): HolderUnwrap => {
    try {
      appendAudit(request.purpose, request.certId, request.kid, outcome, request.requestId);
    } catch (error) {
      return refuse(
        "audit_failed",
        request.purpose,
        error instanceof Error ? error.message : String(error)
      );
    }
    return refuse(outcome, request.purpose, detail);
  };

  return {
    init: () =>
      runtime.serialise(async () => {
        if (initialised()) return { ok: false, error: "already_initialised" };
        const pair = await deps.generateKeyPair();
        const kid = await kidOf(pair.spki);
        const minted = await Promise.all(
          PURPOSES.map(async (purpose) => {
            const bearer = mintBearer(purpose);
            return { purpose, bearer, hash: await hashBearer(bearer) };
          })
        );
        const at = runtime.now();
        const committed = store.transactionSync(() => {
          // Re-checked at commit (plan §5, r1-1): key generation above yielded.
          if (initialised()) return false;
          store.exec(
            "insert into keys (kid, spki, pkcs8, created_at, is_current) values (?, ?, ?, ?, 1)",
            kid,
            base64Encode(pair.spki),
            base64Encode(pair.pkcs8),
            at
          );
          for (const credential of minted) {
            store.exec(
              "insert into credentials (purpose, hash, issued_at, revoked_at) values (?, ?, ?, null)",
              credential.purpose,
              credential.hash,
              at
            );
          }
          writeMeta(store, "initialised", "1");
          writeMeta(store, "initialised_at", at);
          return true;
        });
        if (!committed) return { ok: false, error: "already_initialised" };
        // Read back before answering: the endpoint must never serve a key it cannot prove it stored.
        const stored = keyByKid(kid);
        const credentialCount = store.exec("select count(*) as n from credentials")[0]?.n;
        if (
          stored === null ||
          stored.is_current !== 1 ||
          credentialCount !== PURPOSES.length ||
          !initialised()
        ) {
          throw new Error("initialisation did not read back");
        }
        const bearerFor = (purpose: Purpose): string => {
          const found = minted.find((credential) => credential.purpose === purpose);
          if (found === undefined) throw new Error(`no ${purpose} credential was minted`);
          return found.bearer;
        };
        const credentials: Credentials = {
          derive: bearerFor("derive"),
          qa: bearerFor("qa"),
          release: bearerFor("release")
        };
        return { ok: true, kid, credentials };
      }),

    rotate: () =>
      runtime.serialise(async () => {
        const before = currentKey();
        if (before === null) return { ok: false, error: "not_initialised" };
        if (destroyedAt() !== null) return { ok: false, error: "key_destroyed" };
        const pair = await deps.generateKeyPair();
        const kid = await kidOf(pair.spki);
        const at = runtime.now();
        const outcome = store.transactionSync((): RotateResult => {
          const now = currentKey();
          if (now === null || now.kid !== before.kid) return { ok: false, error: "conflict" };
          if (destroyedAt() !== null) return { ok: false, error: "key_destroyed" };
          store.exec("update keys set is_current = 0 where is_current = 1");
          store.exec(
            "insert into keys (kid, spki, pkcs8, created_at, is_current) values (?, ?, ?, ?, 1)",
            kid,
            base64Encode(pair.spki),
            base64Encode(pair.pkcs8),
            at
          );
          writeMeta(store, "rotated_at", at);
          return { ok: true, kid, previous: before.kid };
        });
        return outcome;
      }),

    destroy: (confirm) =>
      runtime.serialise(async () =>
        store.transactionSync((): DestroyResult => {
          const current = currentKey();
          if (current === null) return { ok: false, error: "not_initialised" };
          if (destroyedAt() !== null) return { ok: false, error: "key_destroyed" };
          const expected = `destroy ${current.kid}`;
          if (confirm !== expected) return { ok: false, error: "confirm_mismatch", expected };
          writeMeta(store, "destroyed_at", runtime.now());
          return { ok: true, kid: current.kid };
        })
      ),

    revoke: (purpose) =>
      runtime.serialise(async () =>
        store.transactionSync((): CredentialResult => {
          if (!initialised()) return { ok: false, error: "not_initialised" };
          store.exec(
            "update credentials set revoked_at = ? where purpose = ? and revoked_at is null",
            runtime.now(),
            purpose
          );
          return { ok: true, purpose, credential: null };
        })
      ),

    reissue: (purpose) =>
      runtime.serialise(async () => {
        if (!initialised()) return { ok: false, error: "not_initialised" };
        const bearer = mintBearer(purpose);
        const hash = await hashBearer(bearer);
        store.transactionSync(() => {
          store.exec(
            "update credentials set hash = ?, issued_at = ?, revoked_at = null where purpose = ?",
            hash,
            runtime.now(),
            purpose
          );
        });
        return { ok: true, purpose, credential: bearer };
      }),

    publicKey: (kid) => {
      if (!initialised()) return { ok: false, error: "not_initialised" };
      if (destroyedAt() !== null) return { ok: false, error: "key_destroyed" };
      const row = kid === undefined ? currentKey() : keyByKid(kid);
      if (row === null) return { ok: false, error: "unknown_kid" };
      return {
        ok: true,
        key: {
          kid: row.kid,
          spki: row.spki,
          alg: "RSA-OAEP-256",
          created_at: row.created_at,
          previous_kids: previousKids()
        }
      };
    },

    health: () => {
      const isInitialised = initialised();
      const destroyed = destroyedAt() !== null;
      const keyState: KeyState = !isInitialised
        ? "uninitialised"
        : destroyed
          ? "destroyed"
          : "active";
      return {
        ok: keyState === "active",
        initialised: isInitialised,
        kid: currentKey()?.kid ?? null,
        key_state: keyState
      };
    },

    unwrap: async (request) => {
      if (!initialised())
        return refuse("not_initialised", null, "the holder has not been initialised");
      const credential = store.exec(
        "select purpose, revoked_at from credentials where hash = ?",
        await hashBearer(request.bearer)
      )[0];
      if (!isCredentialRow(credential))
        return refuse("unknown_credential", null, "no such credential");
      if (credential.purpose !== request.purpose) {
        return refuse(
          "purpose_mismatch",
          credential.purpose,
          `the credential is for ${credential.purpose}, the request says ${request.purpose}`
        );
      }
      if (credential.revoked_at !== null)
        return refuseLogged("revoked", request, `${request.purpose} was revoked`);
      if (destroyedAt() !== null)
        return refuseLogged("key_destroyed", request, "the key was destroyed");
      const key = keyByKid(request.kid);
      if (key === null) return refuseLogged("unknown_kid", request, `no key ${request.kid}`);
      let plaintext: Uint8Array;
      try {
        plaintext = new Uint8Array(
          await crypto.subtle.decrypt({ name: "RSA-OAEP" }, await privateKeyFor(key), request.wrap)
        );
      } catch {
        return refuseLogged("bad_wrap", request, "the wrap did not decrypt under this key");
      }
      const parsed = parseWrappedPayload(plaintext, request.certId);
      if (!parsed.ok) return refuseLogged(parsed.reason, request, parsed.detail);
      let logSeq: number;
      try {
        logSeq = appendAudit(request.purpose, request.certId, request.kid, "ok", request.requestId);
      } catch (error) {
        // No audit row, no key.
        return refuse(
          "audit_failed",
          request.purpose,
          error instanceof Error ? error.message : String(error)
        );
      }
      return {
        ok: true,
        k1: parsed.k1,
        kver: parsed.kver,
        kid: request.kid,
        logSeq,
        purpose: request.purpose
      };
    },

    exportLog: (query) => {
      const rows = store.exec(
        "select seq, at, purpose, cert_id, kid, outcome, request_id from audit where seq > ? and at >= ? and at < ? order by seq limit ?",
        query.after ?? 0,
        query.from ?? "",
        query.to ?? "9999",
        LOG_PAGE
      );
      return rows.filter(isAuditRow).map((row) => ({
        seq: row.seq,
        at: row.at,
        purpose: row.purpose,
        cert_id: row.cert_id,
        kid: row.kid,
        outcome: row.outcome,
        request_id: row.request_id
      }));
    }
  };
}

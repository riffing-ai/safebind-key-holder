import { describe, expect, test } from "bun:test";
import { PURPOSES, base64Encode, kidOf } from "./contract";
import { type HolderDeps, type KeyPairBytes, createHolderCore, webCryptoDeps } from "./holderCore";
import type { SqlStore } from "./store";
import { testRuntime } from "./sqliteTestStore";
import { CERT_A, CERT_B, randomK1, wrapTo } from "./testWrap";

const REQUEST = "req-0001";

async function initialised() {
  const runtime = testRuntime();
  const core = createHolderCore(runtime);
  const init = await core.init();
  if (!init.ok) throw new Error("init failed");
  const key = core.publicKey();
  if (!key.ok) throw new Error("no public key");
  return { runtime, core, init, kid: init.kid, spki: key.key.spki, credentials: init.credentials };
}

/** A key generator the test can hold open, to prove the second init waits for the first. */
function heldGenerator(): HolderDeps & { release: () => void; calls: number } {
  let release = (): void => undefined;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const held: HolderDeps & { release: () => void; calls: number } = {
    calls: 0,
    release: () => release(),
    randomBytes: webCryptoDeps.randomBytes,
    async generateKeyPair(): Promise<KeyPairBytes> {
      held.calls += 1;
      await gate;
      return webCryptoDeps.generateKeyPair();
    }
  };
  return held;
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 5));

describe("init", () => {
  test("init once: one current key, three credentials with their purpose prefix, read back", async () => {
    const { runtime, core, init, kid } = await initialised();
    expect(kid).toHaveLength(22);
    expect(init.credentials.derive.startsWith("khd_")).toBe(true);
    expect(init.credentials.qa.startsWith("khq_")).toBe(true);
    expect(init.credentials.release.startsWith("khr_")).toBe(true);
    expect(runtime.store.exec("select count(*) as n from keys where is_current = 1")[0]?.n).toBe(1);
    expect(runtime.store.exec("select count(*) as n from credentials")[0]?.n).toBe(3);
    // The bearer is never stored: only its hash is.
    for (const purpose of PURPOSES) {
      const stored = runtime.store.exec(
        "select hash from credentials where purpose = ?",
        purpose
      )[0]?.hash;
      expect(stored).not.toBe(init.credentials[purpose]);
      expect(String(stored)).toHaveLength(64);
    }
    const again = await core.init();
    expect(again).toEqual({ ok: false, error: "already_initialised" });
    expect(
      core.publicKey().ok && core.publicKey().ok
        ? (core.publicKey() as { ok: true; key: { kid: string } }).key.kid
        : ""
    ).toBe(kid);
  });

  test("queued init: the second init cannot enter until the first's key generation is released; one kid, one 409", async () => {
    const runtime = testRuntime();
    const held = heldGenerator();
    const core = createHolderCore(runtime, held);
    const first = core.init();
    const second = core.init();
    await settle();
    // Only the first handler has entered: the second is queued behind blockConcurrencyWhile.
    expect(held.calls).toBe(1);
    held.release();
    const [one, two] = await Promise.all([first, second]);
    expect(one.ok).toBe(true);
    expect(two).toEqual({ ok: false, error: "already_initialised" });
    expect(runtime.store.exec("select count(*) as n from keys")[0]?.n).toBe(1);
  });

  test("before init, every public operation refuses not_initialised", async () => {
    const core = createHolderCore(testRuntime());
    expect(core.health()).toEqual({
      ok: false,
      initialised: false,
      kid: null,
      key_state: "uninitialised"
    });
    expect(core.publicKey()).toEqual({ ok: false, error: "not_initialised" });
    const refused = await core.unwrap({
      bearer: "x",
      kid: "k",
      wrap: new Uint8Array(1),
      certId: CERT_A,
      purpose: "derive",
      requestId: REQUEST
    });
    expect(refused.ok).toBe(false);
    if (!refused.ok) expect(refused.error).toBe("not_initialised");
  });
});

describe("unwrap", () => {
  test("round trip under each purpose; the audit row carries purpose, cert, kid, ok and the request id", async () => {
    const { runtime, core, kid, spki, credentials } = await initialised();
    for (const [index, purpose] of PURPOSES.entries()) {
      const k1 = randomK1();
      const wrap = await wrapTo(spki, k1, CERT_A, 7);
      const result = await core.unwrap({
        bearer: credentials[purpose],
        kid,
        wrap,
        certId: CERT_A,
        purpose,
        requestId: `req-${index}`
      });
      expect(result.ok).toBe(true);
      if (!result.ok) continue;
      expect(base64Encode(result.k1)).toBe(base64Encode(k1));
      expect(result.kver).toBe(7);
      expect(result.kid).toBe(kid);
      const row = runtime.store.exec("select * from audit where seq = ?", result.logSeq)[0];
      expect(row).toMatchObject({
        purpose,
        cert_id: CERT_A,
        kid,
        outcome: "ok",
        request_id: `req-${index}`
      });
    }
    expect(core.exportLog({})).toHaveLength(3);
  });

  test("a wrap naming another certificate is cert_mismatch, logged as such; garbage is bad_wrap, logged", async () => {
    const { core, kid, spki, credentials } = await initialised();
    const wrapForB = await wrapTo(spki, randomK1(), CERT_B, 1);
    const mismatch = await core.unwrap({
      bearer: credentials.derive,
      kid,
      wrap: wrapForB,
      certId: CERT_A,
      purpose: "derive",
      requestId: "r1"
    });
    expect(mismatch.ok).toBe(false);
    if (!mismatch.ok) expect(mismatch.error).toBe("cert_mismatch");
    const garbage = await core.unwrap({
      bearer: credentials.derive,
      kid,
      wrap: crypto.getRandomValues(new Uint8Array(256)),
      certId: CERT_A,
      purpose: "derive",
      requestId: "r2"
    });
    expect(garbage.ok).toBe(false);
    if (!garbage.ok) expect(garbage.error).toBe("bad_wrap");
    expect(core.exportLog({}).map((row) => row.outcome)).toEqual(["cert_mismatch", "bad_wrap"]);
  });

  test("purpose mismatch and an unknown credential are refused without a log row", async () => {
    const { core, kid, spki, credentials } = await initialised();
    const wrap = await wrapTo(spki, randomK1(), CERT_A, 1);
    const mismatch = await core.unwrap({
      bearer: credentials.qa,
      kid,
      wrap,
      certId: CERT_A,
      purpose: "derive",
      requestId: "r"
    });
    expect(mismatch.ok).toBe(false);
    if (!mismatch.ok) expect(mismatch.error).toBe("purpose_mismatch");
    const unknown = await core.unwrap({
      bearer: "khd_nope",
      kid,
      wrap,
      certId: CERT_A,
      purpose: "derive",
      requestId: "r"
    });
    expect(unknown.ok).toBe(false);
    if (!unknown.ok) expect(unknown.error).toBe("unknown_credential");
    expect(core.exportLog({})).toHaveLength(0);
  });

  test("an unknown kid is refused and logged", async () => {
    const { core, spki, credentials } = await initialised();
    const wrap = await wrapTo(spki, randomK1(), CERT_A, 1);
    const result = await core.unwrap({
      bearer: credentials.derive,
      kid: "nope",
      wrap,
      certId: CERT_A,
      purpose: "derive",
      requestId: "r"
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe("unknown_kid");
    expect(core.exportLog({}).map((row) => row.outcome)).toEqual(["unknown_kid"]);
  });

  test("no audit row, no key: a store that refuses the append after a good decrypt yields audit_failed and no k1", async () => {
    const runtime = testRuntime();
    const inner: SqlStore = runtime.store;
    let refuseAudit = false;
    const store: SqlStore = {
      exec: (query, ...bindings) => {
        if (refuseAudit && query.startsWith("insert into audit")) throw new Error("disk full");
        return inner.exec(query, ...bindings);
      },
      transactionSync: (closure) => inner.transactionSync(closure)
    };
    const core = createHolderCore({ ...runtime, store });
    const init = await core.init();
    if (!init.ok) throw new Error("init");
    const key = core.publicKey();
    if (!key.ok) throw new Error("key");
    const wrap = await wrapTo(key.key.spki, randomK1(), CERT_A, 1);
    refuseAudit = true;
    const result = await core.unwrap({
      bearer: init.credentials.derive,
      kid: init.kid,
      wrap,
      certId: CERT_A,
      purpose: "derive",
      requestId: "r"
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe("audit_failed");
    expect(JSON.stringify(result)).not.toContain("k1");
  });
});

describe("credentials", () => {
  test("revoking qa refuses qa (logged) while derive and release still unwrap; reissue restores it with a new bearer", async () => {
    const { core, kid, spki, credentials } = await initialised();
    expect(await core.revoke("qa")).toEqual({ ok: true, purpose: "qa", credential: null });
    const wrap = await wrapTo(spki, randomK1(), CERT_A, 1);
    const qa = await core.unwrap({
      bearer: credentials.qa,
      kid,
      wrap,
      certId: CERT_A,
      purpose: "qa",
      requestId: "r1"
    });
    expect(qa.ok).toBe(false);
    if (!qa.ok) expect(qa.error).toBe("revoked");
    for (const purpose of ["derive", "release"] as const) {
      const fine = await core.unwrap({
        bearer: credentials[purpose],
        kid,
        wrap,
        certId: CERT_A,
        purpose,
        requestId: "r2"
      });
      expect(fine.ok).toBe(true);
    }
    const reissued = await core.reissue("qa");
    expect(reissued.ok).toBe(true);
    if (!reissued.ok) return;
    expect(reissued.credential).not.toBe(credentials.qa);
    const old = await core.unwrap({
      bearer: credentials.qa,
      kid,
      wrap,
      certId: CERT_A,
      purpose: "qa",
      requestId: "r3"
    });
    expect(old.ok).toBe(false);
    if (!old.ok) expect(old.error).toBe("unknown_credential");
    const fresh = await core.unwrap({
      bearer: reissued.credential ?? "",
      kid,
      wrap,
      certId: CERT_A,
      purpose: "qa",
      requestId: "r4"
    });
    expect(fresh.ok).toBe(true);
    expect(core.exportLog({}).map((row) => row.outcome)).toEqual(["revoked", "ok", "ok", "ok"]);
  });
});

describe("rotation and destruction", () => {
  test("rotate keeps prior kids: the old wrap still unwraps, public-key?kid=old answers, previous_kids lists it", async () => {
    const { core, kid, spki, credentials } = await initialised();
    const oldWrap = await wrapTo(spki, randomK1(), CERT_A, 1);
    const rotated = await core.rotate();
    expect(rotated.ok).toBe(true);
    if (!rotated.ok) return;
    expect(rotated.previous).toBe(kid);
    expect(rotated.kid).not.toBe(kid);
    const current = core.publicKey();
    expect(current.ok && current.key.kid).toBe(rotated.kid);
    expect(current.ok && current.key.previous_kids).toEqual([kid]);
    const old = core.publicKey(kid);
    expect(old.ok && old.key.kid).toBe(kid);
    const unwrapped = await core.unwrap({
      bearer: credentials.derive,
      kid,
      wrap: oldWrap,
      certId: CERT_A,
      purpose: "derive",
      requestId: "r"
    });
    expect(unwrapped.ok).toBe(true);
    const spkiNew = current.ok ? current.key.spki : "";
    expect(await kidOf(Uint8Array.from(atob(spkiNew), (char) => char.charCodeAt(0)))).toBe(
      rotated.kid
    );
  });

  test("rotate then destroy: both succeed and the key is destroyed; destroy then rotate: the rotate answers key_destroyed", async () => {
    const first = await initialised();
    const rotated = await first.core.rotate();
    expect(rotated.ok).toBe(true);
    const destroyed = await first.core.destroy(`destroy ${rotated.ok ? rotated.kid : ""}`);
    expect(destroyed.ok).toBe(true);
    expect(first.core.health().key_state).toBe("destroyed");

    const second = await initialised();
    expect((await second.core.destroy(`destroy ${second.kid}`)).ok).toBe(true);
    expect(await second.core.rotate()).toEqual({ ok: false, error: "key_destroyed" });
  });

  test("destroy needs the exact confirm phrase, is terminal, and turns every read into key_destroyed (logged on unwrap)", async () => {
    const { core, kid, spki, credentials } = await initialised();
    const wrong = await core.destroy("destroy");
    expect(wrong.ok).toBe(false);
    if (!wrong.ok)
      expect(wrong).toMatchObject({ error: "confirm_mismatch", expected: `destroy ${kid}` });
    const wrap = await wrapTo(spki, randomK1(), CERT_A, 1);
    expect((await core.destroy(`destroy ${kid}`)).ok).toBe(true);
    expect(core.publicKey()).toEqual({ ok: false, error: "key_destroyed" });
    expect(core.health()).toEqual({ ok: false, initialised: true, kid, key_state: "destroyed" });
    const refused = await core.unwrap({
      bearer: credentials.derive,
      kid,
      wrap,
      certId: CERT_A,
      purpose: "derive",
      requestId: "r"
    });
    expect(refused.ok).toBe(false);
    if (!refused.ok) expect(refused.error).toBe("key_destroyed");
    expect(core.exportLog({}).map((row) => row.outcome)).toEqual(["key_destroyed"]);
    expect(await core.destroy(`destroy ${kid}`)).toEqual({ ok: false, error: "key_destroyed" });
  });

  test("serialised rotates: two rotates queued behind a held generation produce one conflict-free chain of two keys", async () => {
    const runtime = testRuntime();
    const held = heldGenerator();
    const core = createHolderCore(runtime, held);
    held.release();
    const init = await core.init();
    expect(init.ok).toBe(true);
    const [one, two] = await Promise.all([core.rotate(), core.rotate()]);
    expect(one.ok && two.ok).toBe(true);
    if (one.ok && two.ok) expect(two.previous).toBe(one.kid);
    expect(runtime.store.exec("select count(*) as n from keys")[0]?.n).toBe(3);
    expect(runtime.store.exec("select count(*) as n from keys where is_current = 1")[0]?.n).toBe(1);
  });
});

describe("export", () => {
  test("the log export pages by seq and filters by time window", async () => {
    const { core, kid, spki, credentials } = await initialised();
    const wrap = await wrapTo(spki, randomK1(), CERT_A, 1);
    for (let index = 0; index < 4; index += 1) {
      await core.unwrap({
        bearer: credentials.derive,
        kid,
        wrap,
        certId: CERT_A,
        purpose: "derive",
        requestId: `r${index}`
      });
    }
    const all = core.exportLog({});
    expect(all.map((row) => row.request_id)).toEqual(["r0", "r1", "r2", "r3"]);
    expect(core.exportLog({ after: 2 }).map((row) => row.seq)).toEqual([3, 4]);
    expect(core.exportLog({ to: "2000-01-01T00:00:00.000Z" })).toHaveLength(0);
  });
});

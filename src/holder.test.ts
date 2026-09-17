import { describe, expect, test } from "bun:test";
import { base64Encode } from "./contract";
import { handleHolderRequest } from "./holder";
import { createHolderCore } from "./holderCore";
import { testRuntime } from "./sqliteTestStore";
import { CERT_A, CERT_B, randomK1, wrapTo } from "./testWrap";

const body = async (response: Response): Promise<Record<string, unknown>> =>
  (await response.json()) as Record<string, unknown>;

const ADMIN = "admin-token-for-tests";
const BASE = "https://holder.example.workers.dev";

function holder(options: { adminToken?: string } = { adminToken: ADMIN }) {
  const { adminToken } = options;
  const core = createHolderCore(testRuntime());
  const lines: Record<string, unknown>[] = [];
  const call = (path: string, init: RequestInit = {}) =>
    handleHolderRequest(new Request(`${BASE}${path}`, init), {
      core,
      adminToken,
      log: (line) => lines.push(line)
    });
  const admin = (path: string, body?: unknown) =>
    call(path, {
      method: "POST",
      headers: { authorization: `Bearer ${adminToken ?? ""}`, "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
  return { core, call, admin, lines };
}

async function initialisedHolder() {
  const h = holder();
  const init = await h.admin("/admin/init");
  expect(init.status).toBe(201);
  const body = (await init.json()) as { kid: string; credentials: Record<string, string> };
  const key = await h.call("/public-key");
  const spki = ((await key.json()) as { spki: string }).spki;
  const unwrap = (bearer: string, payload: Record<string, unknown>, requestId = "req-1") =>
    h.call("/unwrap", {
      method: "POST",
      headers: {
        authorization: `Bearer ${bearer}`,
        "x-request-id": requestId,
        "content-type": "application/json"
      },
      body: JSON.stringify(payload)
    });
  return { ...h, kid: body.kid, credentials: body.credentials, spki, unwrap };
}

describe("public routes", () => {
  test("before init: health says uninitialised, public-key and unwrap answer 503", async () => {
    const h = holder();
    expect(await body(await h.call("/health"))).toEqual({
      ok: false,
      initialised: false,
      kid: null,
      key_state: "uninitialised"
    });
    expect((await h.call("/public-key")).status).toBe(503);
    const unwrap = await h.call("/unwrap", {
      method: "POST",
      headers: { authorization: "Bearer khd_x", "x-request-id": "r" },
      body: JSON.stringify({ kid: "k", wrap: "AA==", cert_id: CERT_A, purpose: "derive" })
    });
    expect(unwrap.status).toBe(503);
  });

  test("round trip over HTTP: 200 with k1, kver, kid and log_seq; one log line", async () => {
    const h = await initialisedHolder();
    const k1 = randomK1();
    const wrap = await wrapTo(h.spki, k1, CERT_A, 3);
    const response = await h.unwrap(h.credentials.derive ?? "", {
      kid: h.kid,
      wrap: base64Encode(wrap),
      cert_id: CERT_A,
      purpose: "derive"
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      k1: string;
      kver: number;
      kid: string;
      log_seq: string;
    };
    expect(body.k1).toBe(base64Encode(k1));
    expect(body.kver).toBe(3);
    expect(body.kid).toBe(h.kid);
    expect(body.log_seq).toBe("1");
    expect(h.lines).toHaveLength(1);
    expect(h.lines[0]).toMatchObject({
      msg: "unwrap",
      purpose: "derive",
      outcome: "ok",
      request_id: "req-1",
      seq: 1
    });
  });

  test("statuses: missing request id 400, wrong purpose 400, revoked 403 with purpose, unknown kid 404, cert mismatch 400, bad wrap 400, unknown credential 401", async () => {
    const h = await initialisedHolder();
    const wrap = base64Encode(await wrapTo(h.spki, randomK1(), CERT_A, 1));
    const payload = { kid: h.kid, wrap, cert_id: CERT_A, purpose: "derive" };
    const noId = await h.call("/unwrap", {
      method: "POST",
      headers: { authorization: `Bearer ${h.credentials.derive}` },
      body: JSON.stringify(payload)
    });
    expect(noId.status).toBe(400);
    expect(await body(noId)).toEqual({ error: "request_id_required" });
    expect((await h.unwrap(h.credentials.qa ?? "", payload)).status).toBe(400);
    await h.admin("/admin/credentials/qa/revoke");
    const revoked = await h.unwrap(h.credentials.qa ?? "", { ...payload, purpose: "qa" });
    expect(revoked.status).toBe(403);
    expect(await body(revoked)).toEqual({ error: "revoked", purpose: "qa" });
    expect((await h.unwrap(h.credentials.derive ?? "", { ...payload, kid: "nope" })).status).toBe(
      404
    );
    const forB = base64Encode(await wrapTo(h.spki, randomK1(), CERT_B, 1));
    const mismatch = await h.unwrap(h.credentials.derive ?? "", { ...payload, wrap: forB });
    expect(mismatch.status).toBe(400);
    expect(((await mismatch.json()) as { error: string }).error).toBe("cert_mismatch");
    const bad = await h.unwrap(h.credentials.derive ?? "", {
      ...payload,
      wrap: base64Encode(new Uint8Array(256))
    });
    expect(bad.status).toBe(400);
    expect(((await bad.json()) as { error: string }).error).toBe("bad_wrap");
    expect((await h.unwrap("khd_unknown", payload)).status).toBe(401);
    expect(
      (await h.unwrap(h.credentials.derive ?? "", { ...payload, cert_id: "not-a-uuid" })).status
    ).toBe(400);
    // Every logged refusal reached Workers Logs too; the unlogged ones did not.
    expect(h.lines.map((line) => line.outcome)).toEqual([
      "revoked",
      "unknown_kid",
      "cert_mismatch",
      "bad_wrap"
    ]);
  });

  test("public-key?kid= answers a prior key after rotation; destroy turns public-key into 410 and health into destroyed", async () => {
    const h = await initialisedHolder();
    const rotate = await h.admin("/admin/rotate");
    expect(rotate.status).toBe(200);
    const { kid: newKid } = (await rotate.json()) as { kid: string };
    const old = await h.call(`/public-key?kid=${h.kid}`);
    expect(old.status).toBe(200);
    expect(((await old.json()) as { kid: string }).kid).toBe(h.kid);
    const current = (await (await h.call("/public-key")).json()) as {
      kid: string;
      previous_kids: string[];
    };
    expect(current.kid).toBe(newKid);
    expect(current.previous_kids).toEqual([h.kid]);
    expect((await h.call("/public-key?kid=nope")).status).toBe(404);
    const wrongConfirm = await h.admin("/admin/destroy", { confirm: "destroy" });
    expect(wrongConfirm.status).toBe(400);
    const destroyed = await h.admin("/admin/destroy", { confirm: `destroy ${newKid}` });
    expect(destroyed.status).toBe(200);
    expect((await h.call("/public-key")).status).toBe(410);
    expect(((await (await h.call("/health")).json()) as { key_state: string }).key_state).toBe(
      "destroyed"
    );
    expect((await h.admin("/admin/rotate")).status).toBe(410);
  });
});

describe("admin routes", () => {
  test("admin routes need the admin token: unset → 503, wrong → 401, second init → 409", async () => {
    const unset = holder({});
    expect((await unset.admin("/admin/init")).status).toBe(503);
    const h = holder();
    const wrong = await h.call("/admin/init", {
      method: "POST",
      headers: { authorization: "Bearer nope" }
    });
    expect(wrong.status).toBe(401);
    expect((await h.admin("/admin/init")).status).toBe(201);
    expect((await h.admin("/admin/init")).status).toBe(409);
  });

  test("reissue returns a fresh bearer once; the log export is NDJSON in seq order with the row count header", async () => {
    const h = await initialisedHolder();
    const reissued = await h.admin("/admin/credentials/release/reissue");
    expect(reissued.status).toBe(200);
    const { credential } = (await reissued.json()) as { credential: string };
    expect(credential.startsWith("khr_")).toBe(true);
    expect((await h.admin("/admin/credentials/other/reissue")).status).toBe(404);
    const wrap = base64Encode(await wrapTo(h.spki, randomK1(), CERT_A, 1));
    for (const requestId of ["a", "b", "c"]) {
      await h.unwrap(
        credential,
        { kid: h.kid, wrap, cert_id: CERT_A, purpose: "release" },
        requestId
      );
    }
    const log = await h.call("/admin/log", { headers: { authorization: `Bearer ${ADMIN}` } });
    expect(log.status).toBe(200);
    expect(log.headers.get("content-type")).toBe("application/x-ndjson");
    expect(log.headers.get("x-holder-log-rows")).toBe("3");
    const rows = (await log.text())
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as { seq: number; request_id: string; purpose: string });
    expect(rows.map((row) => [row.seq, row.request_id, row.purpose])).toEqual([
      [1, "a", "release"],
      [2, "b", "release"],
      [3, "c", "release"]
    ]);
    const paged = await h.call("/admin/log?after=2", {
      headers: { authorization: `Bearer ${ADMIN}` }
    });
    expect(paged.headers.get("x-holder-log-rows")).toBe("1");
  });

  test("unknown paths are 404", async () => {
    const h = await initialisedHolder();
    expect((await h.call("/nope")).status).toBe(404);
    expect((await h.admin("/admin/nope")).status).toBe(404);
  });
});

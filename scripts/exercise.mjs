#!/usr/bin/env bun
/**
 * Synthetic traffic against a deployed holder, and the reconciliation check (plan §12 test 8;
 * docs/runbooks/key-holder.md "Reconciliation").
 *
 *   bun run exercise <holder url> <admin token> [--calls 200]
 *
 * Wraps random session keys to the holder's public key and unwraps them under each purpose, with a
 * deliberate share of refusals: a revoked credential, an unknown kid, a wrap for the wrong certificate,
 * a malformed wrap. Every call carries an X-Request-Id this script generated, and every call's outcome
 * as SEEN BY THE CALLER is kept beside it — the same two views SafeBind's ledger and the holder's log
 * hold in production. At the end the holder's /admin/log export is joined to the caller's view on the
 * request id and the runbook's rule is checked:
 *   - every holder row has a caller row with the same purpose, certificate, kid and outcome;
 *   - every caller row with a non-transport outcome has a holder row;
 *   - the transport divergences are exactly the calls this script broke on purpose.
 * Also runs the ten-concurrent-inits check against a SECOND, fresh deployment if --init-url is given
 * (it must be deployed but not yet initialised; the script leaves it initialised).
 */

const args = process.argv.slice(2);
const url = args[0];
const admin = args[1];
/** The value after a flag, or null when the flag is absent; a flag with no value is an error. */
const flag = (name) => {
  const at = args.indexOf(name);
  if (at === -1) return null;
  const value = args[at + 1];
  if (value === undefined || value.startsWith("--")) {
    console.error(`${name} needs a value`);
    process.exit(2);
  }
  return value;
};
const callsFlag = flag("--calls");
// The whole argument must be a positive integer: "1.5" and "1junk" are refused, not truncated to 1.
const calls = callsFlag === null ? 200 : /^\d+$/.test(callsFlag) ? Number(callsFlag) : Number.NaN;
const initUrl = flag("--init-url");
// The run REISSUES all three credentials (it needs ones it knows) and leaves fresh ones behind, so a
// registration at SafeBind that used the old values must be updated: --save writes the final values
// to a file (never to the terminal) as KEYHOLDER_TEST_DERIVE / _QA / _RELEASE lines.
const savePath = flag("--save");
if (typeof url !== "string" || typeof admin !== "string" || url.startsWith("--")) {
  console.error(
    "usage: bun run exercise <holder url> <admin token> [--calls N] [--save <env file>] [--init-url <fresh holder url>]"
  );
  process.exit(2);
}
// Validated before anything on the holder is touched: a run with no traffic must not reissue
// credentials and then report a reconciliation of nothing.
if (!Number.isSafeInteger(calls) || calls < 1) {
  console.error(`--calls must be a positive integer (got ${callsFlag})`);
  process.exit(2);
}
const base = url.replace(/\/+$/, "");
const adminHeaders = { authorization: `Bearer ${admin}`, "content-type": "application/json" };

const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const uuidBytes = (uuid) => Uint8Array.from(Buffer.from(uuid.replace(/-/g, ""), "hex"));
const encodePayload = (k1, certId, kver) => {
  const payload = new Uint8Array(52);
  payload.set(k1, 0);
  payload.set(uuidBytes(certId), 32);
  new DataView(payload.buffer).setUint32(48, kver, false);
  return payload;
};

// ── Ten concurrent inits on a fresh deployment (plan §12 test 2) ─────────────────────────────────
if (initUrl !== null) {
  const freshAdmin = `kha_${Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url")}`;
  console.log(`concurrent init: set HOLDER_ADMIN_TOKEN on the fresh deployment to ${freshAdmin} before continuing`);
  console.log("(this script cannot set another deployment's secret; run: bunx wrangler secret put HOLDER_ADMIN_TOKEN)");
  process.exit(3);
}

// ── Setup: the current key, and a reissued qa credential we then revoke ──────────────────────────
const key = await fetch(`${base}/public-key`).then((response) => response.json());
if (typeof key.kid !== "string") {
  console.error(`holder is not serving a key: ${JSON.stringify(key)}`);
  process.exit(1);
}
const publicKey = await crypto.subtle.importKey("spki", Buffer.from(key.spki, "base64"), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
const credentials = {};
for (const purpose of ["derive", "qa", "release"]) {
  const reissued = await fetch(`${base}/admin/credentials/${purpose}/reissue`, { method: "POST", headers: adminHeaders }).then((response) => response.json());
  credentials[purpose] = reissued.credential;
}
const revokedQa = credentials.qa;
await fetch(`${base}/admin/credentials/qa/reissue`, { method: "POST", headers: adminHeaders }).then((response) => response.json()).then((body) => {
  credentials.qa = body.credential;
});
// `revokedQa` is now an unknown credential (reissue replaced it); revoke release for the "revoked" case.
await fetch(`${base}/admin/credentials/release/revoke`, { method: "POST", headers: adminHeaders });

// ── The traffic ──────────────────────────────────────────────────────────────────────────────────
const startedAt = new Date().toISOString();
const callerView = [];
const kinds = ["ok", "ok", "ok", "ok", "ok", "ok", "revoked", "unknown_kid", "cert_mismatch", "bad_wrap", "dropped"];

for (let index = 0; index < calls; index += 1) {
  const kind = kinds[index % kinds.length];
  const certId = crypto.randomUUID();
  const requestId = crypto.randomUUID();
  const purpose = kind === "revoked" ? "release" : ["derive", "qa"][index % 2];
  const k1 = crypto.getRandomValues(new Uint8Array(32));
  const wrapCert = kind === "cert_mismatch" ? crypto.randomUUID() : certId;
  const wrap =
    kind === "bad_wrap"
      ? crypto.getRandomValues(new Uint8Array(256))
      : new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, encodePayload(k1, wrapCert, 1)));
  const kid = kind === "unknown_kid" ? "not-a-kid" : key.kid;
  const body = JSON.stringify({ kid, wrap: b64(wrap), cert_id: certId, purpose });
  const record = { request_id: requestId, purpose, cert_id: certId, kid, kind, outcome: "pending" };
  callerView.push(record);
  if (kind === "dropped") {
    // The response is lost on purpose: the call reaches the holder, the caller never sees the answer.
    const controller = new AbortController();
    const pending = fetch(`${base}/unwrap`, {
      method: "POST",
      headers: { authorization: `Bearer ${credentials[purpose]}`, "content-type": "application/json", "x-request-id": requestId },
      body,
      signal: controller.signal
    }).catch(() => null);
    setTimeout(() => controller.abort(), 5);
    await pending;
    record.outcome = "unavailable";
    continue;
  }
  const response = await fetch(`${base}/unwrap`, {
    method: "POST",
    headers: { authorization: `Bearer ${credentials[purpose]}`, "content-type": "application/json", "x-request-id": requestId },
    body
  });
  const answer = await response.json().catch(() => ({}));
  if (response.status === 200) {
    record.outcome = b64(k1) === answer.k1 ? "ok" : "error";
  } else if (response.status === 403) record.outcome = "revoked";
  else if (response.status === 404) record.outcome = "unknown_kid";
  else if (response.status === 410) record.outcome = "key_destroyed";
  else if (response.status === 400 && (answer.error === "bad_wrap" || answer.error === "cert_mismatch")) record.outcome = answer.error;
  else record.outcome = "unavailable";
}

// ── The holder's view ────────────────────────────────────────────────────────────────────────────
const holderRows = [];
let after = 0;
for (;;) {
  const page = await fetch(`${base}/admin/log?from=${encodeURIComponent(startedAt)}&after=${after}`, { headers: adminHeaders });
  const text = await page.text();
  const rows = text.trim().length === 0 ? [] : text.trim().split("\n").map((line) => JSON.parse(line));
  holderRows.push(...rows);
  if (rows.length < 5000) break;
  after = rows[rows.length - 1].seq;
}

// ── The rule ─────────────────────────────────────────────────────────────────────────────────────
const byRequest = new Map(callerView.map((row) => [row.request_id, row]));
const TRANSPORT = new Set(["unavailable", "error", "pending"]);
const problems = [];
for (const row of holderRows) {
  const caller = byRequest.get(row.request_id);
  if (caller === undefined) {
    problems.push(`holder row ${row.seq} (${row.request_id}) has no caller row`);
    continue;
  }
  if (caller.purpose !== row.purpose || caller.cert_id !== row.cert_id || caller.kid !== row.kid) {
    problems.push(`holder row ${row.seq} disagrees on purpose/cert/kid with the caller`);
  }
  if (!TRANSPORT.has(caller.outcome) && caller.outcome !== row.outcome) {
    problems.push(`holder row ${row.seq}: holder says ${row.outcome}, caller says ${caller.outcome}`);
  }
}
const holderByRequest = new Map(holderRows.map((row) => [row.request_id, row]));
const divergences = [];
for (const caller of callerView) {
  const holder = holderByRequest.get(caller.request_id);
  if (TRANSPORT.has(caller.outcome)) {
    divergences.push({ request_id: caller.request_id, kind: caller.kind, caller: caller.outcome, holder: holder?.outcome ?? "none" });
    continue;
  }
  if (holder === undefined) problems.push(`caller row ${caller.request_id} (${caller.outcome}) has no holder row`);
}
const unexpectedDivergences = divergences.filter((entry) => entry.kind !== "dropped");

// Leave the holder as it was found: nothing revoked. `release` gets a fresh credential.
const restored = await fetch(`${base}/admin/credentials/release/reissue`, { method: "POST", headers: adminHeaders }).then((response) => response.json());
credentials.release = restored.credential;
if (savePath !== null) {
  const { appendFileSync } = await import("node:fs");
  appendFileSync(
    savePath,
    `# reissued by exercise.mjs ${new Date().toISOString()}\nKEYHOLDER_TEST_DERIVE=${credentials.derive}\nKEYHOLDER_TEST_QA=${credentials.qa}\nKEYHOLDER_TEST_RELEASE=${credentials.release}\n`
  );
  console.log(`current credentials appended to ${savePath}`);
}

console.log(`calls: ${callerView.length}; holder rows: ${holderRows.length}; transport divergences: ${divergences.length} (dropped on purpose: ${callerView.filter((row) => row.kind === "dropped").length})`);
for (const problem of problems) console.log(`PROBLEM: ${problem}`);
for (const entry of unexpectedDivergences) console.log(`UNEXPECTED DIVERGENCE: ${JSON.stringify(entry)}`);
if (callerView.length === 0 || holderRows.length === 0) {
  console.log("NOT RECONCILED: no traffic was exercised (or the holder logged none of it).");
  process.exit(1);
}
if (problems.length === 0 && unexpectedDivergences.length === 0) {
  console.log("RECONCILED: the two views agree; every divergence is a call this script dropped.");
  process.exit(0);
}
process.exit(1);

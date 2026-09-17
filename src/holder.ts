/**
 * The HTTP layer of the holder (CONTRACT.md): three public operations, the admin operations behind
 * HOLDER_ADMIN_TOKEN, and the audit export. Pure routing over `HolderCore`; the Durable Object in
 * index.ts is the only production caller, and the tests call it with a bun:sqlite-backed core.
 */

import {
  type HolderOutcome,
  type Purpose,
  base64Encode,
  isHolderOutcome,
  isPurpose,
  isUuid,
  sha256Hex,
  tryBase64Decode
} from "./contract";
import type { HolderCore, HolderUnwrap, UnwrapRefusal } from "./holderCore";

export interface HolderHttpDeps {
  core: HolderCore;
  /** The publisher's admin token (a wrangler secret). Unset = every admin route answers 503. */
  adminToken: string | undefined;
  /** One JSON line per unwrap, for Workers Logs / Logpush. Defaults to console.log. */
  log?: (line: Record<string, unknown>) => void;
}

const json = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

const bearerOf = (request: Request): string | null => {
  const header = request.headers.get("authorization") ?? "";
  const match = /^Bearer\s+(\S+)$/i.exec(header);
  return match?.[1] ?? null;
};

/** Constant-time on the digests: the comparison must not leak how much of the token matched. */
async function tokensMatch(presented: string, expected: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const [left, right] = await Promise.all([
    sha256Hex(encoder.encode(presented)),
    sha256Hex(encoder.encode(expected))
  ]);
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

const REFUSAL_STATUS: Record<UnwrapRefusal, number> = {
  not_initialised: 503,
  unknown_credential: 401,
  purpose_mismatch: 400,
  revoked: 403,
  unknown_kid: 404,
  key_destroyed: 410,
  bad_wrap: 400,
  cert_mismatch: 400,
  audit_failed: 500
};

/** The refusals the core logged (they name a credential): the same outcome goes to Workers Logs. */
const loggedOutcome = (error: UnwrapRefusal): HolderOutcome | null =>
  isHolderOutcome(error) ? error : null;

const readJson = async (request: Request): Promise<Record<string, unknown> | null> => {
  try {
    const body: unknown = await request.json();
    return typeof body === "object" && body !== null ? (body as Record<string, unknown>) : null;
  } catch {
    return null;
  }
};

export async function handleHolderRequest(
  request: Request,
  deps: HolderHttpDeps
): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = request.method.toUpperCase();
  const log = deps.log ?? ((line) => console.log(JSON.stringify(line)));

  if (path === "/health" && method === "GET") return json(deps.core.health());

  if (path === "/public-key" && method === "GET") {
    const kid = url.searchParams.get("kid") ?? undefined;
    const answer = deps.core.publicKey(kid);
    if (answer.ok) return json(answer.key);
    const status =
      answer.error === "not_initialised" ? 503 : answer.error === "key_destroyed" ? 410 : 404;
    return json({ error: answer.error }, status);
  }

  if (path === "/unwrap" && method === "POST") {
    const bearer = bearerOf(request);
    if (bearer === null) return json({ error: "unknown_credential" }, 401);
    const requestId = request.headers.get("x-request-id");
    if (requestId === null || requestId.length === 0 || requestId.length > 128) {
      return json({ error: "request_id_required" }, 400);
    }
    const body = await readJson(request);
    const wrap = tryBase64Decode(body?.wrap);
    if (
      body === null ||
      typeof body.kid !== "string" ||
      body.kid.length === 0 ||
      wrap === null ||
      !isUuid(body.cert_id) ||
      !isPurpose(body.purpose)
    ) {
      return json({ error: "invalid_body" }, 400);
    }
    const purpose: Purpose = body.purpose;
    const result: HolderUnwrap = await deps.core.unwrap({
      bearer,
      kid: body.kid,
      wrap,
      certId: body.cert_id,
      purpose,
      requestId
    });
    if (result.ok) {
      log({
        msg: "unwrap",
        purpose,
        cert_id: body.cert_id,
        kid: body.kid,
        outcome: "ok",
        request_id: requestId,
        seq: result.logSeq
      });
      return json({
        k1: base64Encode(result.k1),
        kver: result.kver,
        kid: result.kid,
        log_seq: String(result.logSeq)
      });
    }
    const logged = loggedOutcome(result.error);
    if (logged !== null) {
      log({
        msg: "unwrap",
        purpose,
        cert_id: body.cert_id,
        kid: body.kid,
        outcome: logged,
        request_id: requestId
      });
    }
    return json(
      result.error === "revoked"
        ? { error: "revoked", purpose: result.purpose }
        : { error: result.error, detail: result.detail },
      REFUSAL_STATUS[result.error]
    );
  }

  if (path.startsWith("/admin/")) {
    if (deps.adminToken === undefined || deps.adminToken.length === 0)
      return json({ error: "admin_token_unset" }, 503);
    const bearer = bearerOf(request);
    if (bearer === null || !(await tokensMatch(bearer, deps.adminToken)))
      return json({ error: "unauthorised" }, 401);
    return handleAdmin(path, method, request, url, deps);
  }

  return json({ error: "not_found" }, 404);
}

async function handleAdmin(
  path: string,
  method: string,
  request: Request,
  url: URL,
  deps: HolderHttpDeps
): Promise<Response> {
  const { core } = deps;
  if (path === "/admin/init" && method === "POST") {
    const result = await core.init();
    return result.ok
      ? json({ kid: result.kid, credentials: result.credentials }, 201)
      : json({ error: result.error }, 409);
  }
  if (path === "/admin/rotate" && method === "POST") {
    const result = await core.rotate();
    if (result.ok) return json({ kid: result.kid, previous: result.previous });
    const status =
      result.error === "not_initialised" ? 503 : result.error === "key_destroyed" ? 410 : 409;
    return json({ error: result.error }, status);
  }
  if (path === "/admin/destroy" && method === "POST") {
    const body = await readJson(request);
    const confirm = typeof body?.confirm === "string" ? body.confirm : "";
    const result = await core.destroy(confirm);
    if (result.ok) return json({ kid: result.kid, key_state: "destroyed" });
    const status =
      result.error === "not_initialised" ? 503 : result.error === "key_destroyed" ? 410 : 400;
    return json(
      {
        error: result.error,
        ...(result.expected !== undefined ? { expected: result.expected } : {})
      },
      status
    );
  }
  const credential = /^\/admin\/credentials\/([a-z]+)\/(revoke|reissue)$/.exec(path);
  if (credential !== null && method === "POST") {
    const purpose = credential[1];
    if (!isPurpose(purpose)) return json({ error: "unknown_purpose" }, 404);
    const result =
      credential[2] === "revoke" ? await core.revoke(purpose) : await core.reissue(purpose);
    if (!result.ok) return json({ error: result.error }, 503);
    return json({
      purpose,
      ...(result.credential !== null ? { credential: result.credential } : { revoked: true })
    });
  }
  if (path === "/admin/log" && method === "GET") {
    const after = Number.parseInt(url.searchParams.get("after") ?? "0", 10);
    const rows = core.exportLog({
      from: url.searchParams.get("from") ?? undefined,
      to: url.searchParams.get("to") ?? undefined,
      after: Number.isFinite(after) ? after : 0
    });
    const body = rows.map((row) => JSON.stringify(row)).join("\n");
    return new Response(body.length > 0 ? `${body}\n` : "", {
      status: 200,
      headers: { "content-type": "application/x-ndjson", "x-holder-log-rows": String(rows.length) }
    });
  }
  return json({ error: "not_found" }, 404);
}

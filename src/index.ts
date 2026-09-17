/**
 * The deployable: a Worker whose every request goes to one Durable Object, `Holder`, which owns the
 * key material, the credential hashes and the audit log in its SQLite storage. See README.md for the
 * publisher's deploy steps and CONTRACT.md for what the routes promise.
 */

import { DurableObject } from "cloudflare:workers";
import { handleHolderRequest } from "./holder";
import { type HolderCore, createHolderCore } from "./holderCore";
import { type SqlRow, type SqlStore, ensureSchema } from "./store";

export interface Env {
  HOLDER: DurableObjectNamespace<Holder>;
  /** The publisher's admin token, set by `bun run init` as a wrangler secret. */
  HOLDER_ADMIN_TOKEN?: string;
}

/** One instance per deployment: every request is routed to the object named "holder". */
const HOLDER_NAME = "holder";

export class Holder extends DurableObject<Env> {
  private readonly core: HolderCore;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    const store: SqlStore = {
      // The schema stores only text and integers, so every row the cursor yields fits SqlRow.
      exec: (query, ...bindings) => ctx.storage.sql.exec(query, ...bindings).toArray() as SqlRow[],
      transactionSync: (closure) => ctx.storage.transactionSync(closure)
    };
    ensureSchema(store);
    this.core = createHolderCore({
      store,
      serialise: (closure) => ctx.blockConcurrencyWhile(closure),
      now: () => new Date().toISOString()
    });
  }

  override fetch(request: Request): Promise<Response> {
    return handleHolderRequest(request, {
      core: this.core,
      adminToken: this.env.HOLDER_ADMIN_TOKEN
    });
  }
}

export default {
  fetch(request: Request, env: Env): Promise<Response> {
    const stub = env.HOLDER.get(env.HOLDER.idFromName(HOLDER_NAME));
    return stub.fetch(request);
  }
} satisfies ExportedHandler<Env>;

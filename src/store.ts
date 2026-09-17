/**
 * The holder's storage seam. The Durable Object's SQLite (`ctx.storage.sql` + `transactionSync` +
 * `blockConcurrencyWhile`) and bun's built-in sqlite (tests) both run the same SQL through this
 * interface, so the tests exercise the real schema and the real transactions, not a stand-in.
 */

export type SqlValue = string | number | null;
export type SqlRow = Record<string, SqlValue>;

export interface SqlStore {
  /** Run one statement and return its rows (empty for statements without a result). Synchronous, like
   *  the Durable Object's `sql.exec`. */
  exec(query: string, ...bindings: SqlValue[]): SqlRow[];
  /** A synchronous transaction: everything inside commits or nothing does. */
  transactionSync<T>(closure: () => T): T;
}

export interface HolderRuntime {
  store: SqlStore;
  /**
   * Run `closure` with no other event delivered to the object until it settles — the Durable Object's
   * `blockConcurrencyWhile`. Every admin mutation runs inside it (plan §5): the object delivers one
   * event at a time, but a handler that awaits key generation yields, and without this a second
   * request could run in the gap.
   */
  serialise<T>(closure: () => Promise<T>): Promise<T>;
  now(): string;
}

export const SCHEMA = [
  "create table if not exists meta (key text primary key, value text not null)",
  // spki / pkcs8 are standard base64 of the DER bytes. is_current: exactly one row while the holder is
  // live. A rotated-out key stays for unwrap (CONTRACT.md: rotation keeps every prior version).
  "create table if not exists keys (kid text primary key, spki text not null, pkcs8 text not null, created_at text not null, is_current integer not null default 0)",
  // One row per purpose. `hash` is hex SHA-256 of the bearer; the bearer itself is returned once at
  // init or reissue and never stored.
  "create table if not exists credentials (purpose text primary key, hash text not null, issued_at text not null, revoked_at text)",
  // The audit log. Appended after the decrypt and before the answer; never updated or deleted by the
  // holder's own code.
  "create table if not exists audit (seq integer primary key autoincrement, at text not null, purpose text not null, cert_id text not null, kid text not null, outcome text not null, request_id text not null)",
  "create index if not exists audit_at on audit (at)"
] as const;

export function ensureSchema(store: SqlStore): void {
  for (const statement of SCHEMA) store.exec(statement);
}

/** A meta value, or null when unset. */
export function readMeta(store: SqlStore, key: string): string | null {
  const row = store.exec("select value from meta where key = ?", key)[0];
  return typeof row?.value === "string" ? row.value : null;
}

export function writeMeta(store: SqlStore, key: string, value: string): void {
  store.exec(
    "insert into meta (key, value) values (?, ?) on conflict (key) do update set value = excluded.value",
    key,
    value
  );
}

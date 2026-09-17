/**
 * The test runtime: bun's built-in sqlite behind the same `SqlStore` interface the Durable Object
 * adapts, and a FIFO `serialise` with the semantics of `blockConcurrencyWhile` (the next closure does
 * not start until the previous one has settled). Tests import this; production never does.
 */

import { Database } from "bun:sqlite";
import type { HolderRuntime, SqlRow, SqlStore, SqlValue } from "./store";

export function sqliteStore(): SqlStore & { db: Database } {
  const db = new Database(":memory:");
  return {
    db,
    exec: (query: string, ...bindings: SqlValue[]): SqlRow[] =>
      // bun:sqlite answers rows as plain objects, the same shape the Durable Object's cursor yields.
      db.query(query).all(...bindings) as SqlRow[],
    transactionSync: <T>(closure: () => T): T => db.transaction(closure)()
  };
}

export function fifoSerialiser(): HolderRuntime["serialise"] {
  let chain: Promise<unknown> = Promise.resolve();
  return <T>(closure: () => Promise<T>): Promise<T> => {
    const run = chain.then(closure);
    chain = run.then(
      () => undefined,
      () => undefined
    );
    return run;
  };
}

export function testRuntime(): HolderRuntime & { store: SqlStore & { db: Database } } {
  const store = sqliteStore();
  return { store, serialise: fifoSerialiser(), now: () => new Date().toISOString() };
}

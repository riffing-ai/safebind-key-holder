#!/usr/bin/env bun
/**
 * One-time initialisation of a deployed key holder (README.md "Deploy").
 *
 *   bun run init https://safebind-key-holder.<subdomain>.workers.dev
 *
 * 1. Generates the admin token and stores it as the Worker's HOLDER_ADMIN_TOKEN secret (wrangler).
 * 2. Calls POST /admin/init with it. The holder generates its keypair, mints the three credentials and
 *    answers once.
 * 3. Prints the kid, the three credentials and the admin token. Nothing is written to disk.
 *
 * Runs in the publisher's shell against the publisher's account. SafeBind never sees these values.
 */

import { spawnSync } from "node:child_process";

const url = process.argv[2];
if (typeof url !== "string" || !/^https:\/\//.test(url)) {
  console.error("usage: bun run init https://safebind-key-holder.<subdomain>.workers.dev");
  process.exit(2);
}
const base = url.replace(/\/+$/, "");

const health = await fetch(`${base}/health`).then((response) => response.json()).catch(() => null);
if (health === null) {
  console.error(`could not reach ${base}/health — is the Worker deployed?`);
  process.exit(1);
}
if (health.initialised === true) {
  console.error(`this holder is already initialised (kid ${health.kid}); nothing to do`);
  process.exit(1);
}

const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
const adminToken = `kha_${Buffer.from(tokenBytes).toString("base64url")}`;

console.log("storing the admin token as the Worker's HOLDER_ADMIN_TOKEN secret…");
const put = spawnSync("bunx", ["wrangler", "secret", "put", "HOLDER_ADMIN_TOKEN"], {
  input: `${adminToken}\n`,
  stdio: ["pipe", "inherit", "inherit"],
  shell: process.platform === "win32"
});
if (put.status !== 0) {
  console.error("wrangler secret put failed; the holder was not initialised");
  process.exit(1);
}

// Secrets propagate within seconds; the init retries briefly on 503 admin_token_unset.
let answer = null;
for (let attempt = 0; attempt < 12; attempt += 1) {
  const response = await fetch(`${base}/admin/init`, {
    method: "POST",
    headers: { authorization: `Bearer ${adminToken}` }
  });
  const body = await response.json().catch(() => ({}));
  if (response.status === 201) {
    answer = body;
    break;
  }
  if (response.status === 503 && body.error === "admin_token_unset") {
    await new Promise((resolve) => setTimeout(resolve, 5000));
    continue;
  }
  console.error(`init failed: ${response.status} ${JSON.stringify(body)}`);
  process.exit(1);
}
if (answer === null) {
  console.error("the new secret did not become visible to the Worker in time; run `bun run init` again");
  process.exit(1);
}

// Read back through the public route before declaring success, as the holder itself did.
const key = await fetch(`${base}/public-key`).then((response) => response.json());
if (key.kid !== answer.kid) {
  console.error(`public-key answered kid ${key.kid}, init answered ${answer.kid}; do not use this holder`);
  process.exit(1);
}

console.log("");
console.log("Initialised. Paste the URL and the three credentials into SafeBind → Settings → Key holder.");
console.log("These are shown ONCE. Keep the admin token where you keep secrets.");
console.log("");
console.log(`url:      ${base}`);
console.log(`kid:      ${answer.kid}`);
console.log(`derive:   ${answer.credentials.derive}`);
console.log(`qa:       ${answer.credentials.qa}`);
console.log(`release:  ${answer.credentials.release}`);
console.log(`admin:    ${adminToken}`);

# SafeBind key holder

A small Cloudflare Worker you run in **your own** Cloudflare account. It holds the key your visitors'
sessions are encrypted to before they leave the page, and it opens a session only when SafeBind asks —
writing one line in a log you own for every call. SafeBind never holds the private key, and never holds
the admin token that controls this deployment.

What it gives you, in plain terms: SafeBind receives your session evidence already encrypted, cannot open
it on its own, and every open it performs (at the consumer's affirmation, for a bounded quality check, or
for a retrieval you paid for) is a line in your log, with its purpose.

**One sentence to keep in mind:** *key loss destroys your evidence, and there is no recovery.* The private
key never leaves this Worker's storage and there is no export. Do not delete the Worker or its Durable
Object while you have evidence you may need.

## What it costs

Nothing on the Workers Free plan for most publishers. The holder makes one request and writes one small
row per open; one certificate needs about four requests in total. The Free plan allows 10 ms of CPU per
request; one RSA-2048 unwrap measured 0.5 ms in bun on a laptop (Workers run the same Web Crypto), and
the Durable Object's own CPU allowance is separate and far larger. Free-plan limits (Cloudflare, 2026):
100,000 Worker requests a day, 100,000 Durable Object requests a day, 100,000 database rows written a day,
5 GB stored. That covers roughly 25,000 certificates a day. Above that, Workers Paid is $5 a month.

Workers Logs keep the last 3 days on Free and 7 on Paid; the holder's own audit table keeps every row
for as long as the Worker exists, and you can export it at any time (below).

## Deploy (once, about ten minutes)

You need a Cloudflare account and [Bun](https://bun.sh).

```bash
git clone https://github.com/riffing-ai/safebind-key-holder && cd safebind-key-holder
bun install
bunx wrangler login                 # opens your browser; sign in to YOUR Cloudflare account
bun run deploy                      # creates the Worker safebind-key-holder in your account
bun run init https://safebind-key-holder.<your-subdomain>.workers.dev
```

`bun run init` generates the admin token, stores it as the Worker's secret, initialises the key, and prints
**three credentials once**:

```
kid:      3fJ…
derive:   khd_…
qa:       khq_…
release:  khr_…
```

Paste the URL and the three credentials into SafeBind's console under **Settings → Key holder**. Keep
the admin token the script printed somewhere safe: it is the only way to rotate, revoke or destroy.

SafeBind then reads your public key several times to confirm it is stable, and shows the holder as
**active**. Until Phase 4 of SafeBind's rollout reaches your account nothing is wrapped to it; after that
your tag encrypts to this key.

## Day to day

- **Revoke one purpose** (say, quality checks) without touching the others:
  `curl -X POST -H "Authorization: Bearer $ADMIN" $URL/admin/credentials/qa/revoke`
- **Issue a new credential** for a purpose (revokes the old one):
  `curl -X POST -H "Authorization: Bearer $ADMIN" $URL/admin/credentials/qa/reissue` — then paste the new
  value into SafeBind's console (Settings → Key holder → Replace credentials).
- **Rotate the key**: `curl -X POST -H "Authorization: Bearer $ADMIN" $URL/admin/rotate`. Old keys are
  kept, so sessions wrapped to them still open. SafeBind notices the new key on its next check.
- **Export your log**: `curl -H "Authorization: Bearer $ADMIN" "$URL/admin/log?from=2026-09-01T00:00:00Z&to=2026-10-01T00:00:00Z"`
  gives one JSON line per open (`purpose`, `cert_id`, `kid`, `outcome`, `request_id`, time), 5,000 a
  page (pass the last `seq` as `after=` for the next page). SafeBind's console exports its own ledger of
  the calls it made in the same shape, so you can lay the two side by side; `request_id` joins them.
- **Destroy the key** (irreversible; every unopened session becomes permanently unreadable):
  `curl -X POST -H "Authorization: Bearer $ADMIN" -d '{"confirm":"destroy <kid>"}' $URL/admin/destroy`.
  SafeBind's next check sees it and stops serving your public key.

Every open is also printed as one JSON line in Workers Logs, so Logpush works if you already use it.

## What SafeBind can and cannot do with this

- It can call `/unwrap` with a credential you issued, and only for that credential's purpose.
- It cannot read your log except through you, cannot edit or delete a line, and cannot rotate, revoke or
  destroy anything: those need the admin token, which only you hold.
- The private key is readable by anyone who administers your Cloudflare account, and by Cloudflare. That
  is real separation from SafeBind; it is not a hardware security module. If you need one, the AWS KMS
  variant (`aws/template.yaml`) puts the key in KMS in your AWS account, with CloudTrail as the log.

## For developers

`CONTRACT.md` is the contract. `src/holderCore.ts` is the logic, `src/holder.ts` the HTTP routes,
`src/index.ts` the Worker and Durable Object. `bun test` runs everything against bun's built-in SQLite
with the same SQL the Durable Object runs.

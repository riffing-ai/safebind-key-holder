# The key-holder contract

A key holder keeps the private half of a keypair that SafeBind's tag wraps session keys to, and opens
those wraps only when SafeBind asks under a named purpose, writing one audit line per call in a log the
publisher owns. This document is the contract every implementation is tested against; `src/contract.ts`
is the same contract as code (the seal worker imports it).

Two implementations exist:

- **The Cloudflare Worker in this package**, which a publisher deploys into their own Cloudflare account
  (README.md). It serves the HTTP routes below itself.
- **AWS KMS**, where there is no service to run: SafeBind calls `Decrypt` through a role per purpose in
  the publisher's AWS account, and CloudTrail is the log (`aws/template.yaml`).

## Algorithm and key identity

- RSA-2048, RSAES-OAEP with SHA-256 (`alg: "RSA-OAEP-256"`).
- `kid` = base64url of the first 16 bytes of SHA-256 over the SubjectPublicKeyInfo DER. It is derived,
  never assigned, so every party computes the same identifier from the same key.
- Rotation creates a new `kid`; every prior key is kept and still unwraps.

## The wrapped payload

52 bytes, encrypted in the browser under the public key:

| bytes | content |
|---|---|
| 0–31 | `K₁`, SafeBind's half of the session key |
| 32–47 | the certificate id, as its 16 raw UUID bytes |
| 48–51 | `kver`, big-endian uint32 |

The holder checks that the certificate inside the wrap is the certificate the caller named. A wrap for
another certificate is refused as `cert_mismatch`, so an audit line can never describe a different
certificate than the one that was opened. (With KMS the decrypt is done by KMS and this check is done by
SafeBind's client afterwards; CloudTrail therefore shows a successful `Decrypt` for such a call and
SafeBind's ledger shows `cert_mismatch`.)

## Routes (the Worker)

All bodies are JSON; keys and wraps are standard base64.

### `GET /public-key[?kid=<kid>]` — no auth, not audited

`200 {"kid","spki","alg":"RSA-OAEP-256","created_at","previous_kids":[…]}` for the current key, or for the
named prior key. `503 {"error":"not_initialised"}` before initialisation; `410 {"error":"key_destroyed"}`
after the publisher destroyed the key; `404 {"error":"unknown_kid"}`.

### `POST /unwrap` — `Authorization: Bearer <credential>`, `X-Request-Id: <caller's id>`

Body: `{"kid","wrap","cert_id","purpose"}`. The credential fixes the purpose (`derive`, `qa`, `release`);
a body purpose that disagrees is `400 purpose_mismatch`.

Order inside the holder: authenticate → decrypt → **commit the audit row with the real outcome → answer**.
A storage failure after a successful decrypt answers `500 audit_failed` and returns nothing: no audit row,
no key.

| Status | Body | Audited? |
|---|---|---|
| 200 | `{"k1","kver","kid","log_seq"}` | yes, `ok` |
| 400 | `{"error":"request_id_required"}`, `{"error":"invalid_body"}`, `{"error":"purpose_mismatch"}` | no |
| 400 | `{"error":"bad_wrap"}` (did not decrypt), `{"error":"cert_mismatch"}` | yes |
| 401 | `{"error":"unknown_credential"}` | no |
| 403 | `{"error":"revoked","purpose"}` | yes |
| 404 | `{"error":"unknown_kid"}` | yes |
| 410 | `{"error":"key_destroyed"}` | yes |
| 500 | `{"error":"audit_failed"}` | — |
| 503 | `{"error":"not_initialised"}` | no |

### `GET /health` — no auth, no secrets, not audited

`200 {"ok","initialised","kid","key_state"}` with `key_state` one of `active`, `destroyed`,
`uninitialised`. Always 200 when the holder answers: the body is the evidence; a non-200 means the
transport failed, which is never evidence about the key.

### Admin routes — `Authorization: Bearer <HOLDER_ADMIN_TOKEN>`

The admin token belongs to the publisher. SafeBind never holds it.

- `POST /admin/init` → `201 {"kid","credentials":{"derive","qa","release"}}` once; `409 already_initialised`.
- `POST /admin/rotate` → `200 {"kid","previous"}`; prior keys are kept.
- `POST /admin/credentials/{derive|qa|release}/revoke` → `200 {"purpose","revoked":true}`.
- `POST /admin/credentials/{purpose}/reissue` → `200 {"purpose","credential"}` (shown once).
- `POST /admin/destroy` with `{"confirm":"destroy <current kid>"}` → `200 {"kid","key_state":"destroyed"}`.
  Terminal. After this `/public-key` and `/unwrap` answer 410 and `/health` says `destroyed`: this is the
  **authoritative** signal SafeBind's cache may act on.
- `GET /admin/log?from=<iso>&to=<iso>&after=<seq>` → NDJSON, one audit row per line, 5,000 rows a page
  (`x-holder-log-rows` says how many; pass the last `seq` as `after` for the next page).

## The audit row

```json
{"seq":1,"at":"2026-09-16T21:00:00.000Z","purpose":"derive","cert_id":"…","kid":"…","outcome":"ok","request_id":"…"}
```

`request_id` is the caller's `X-Request-Id`, so a row matches one row in SafeBind's own ledger. Outcomes:
`ok`, `revoked`, `unknown_kid`, `key_destroyed`, `bad_wrap`, `cert_mismatch`. Refusals that name no
credential (`unknown_credential`, `not_initialised`, `purpose_mismatch`) are not audited: there is no
purpose the row could carry.

## What SafeBind's caller sees

One mapping, shared by both clients (`stateForHolderAnswer` in `src/contract.ts`):

| Observed | Result | Moves the holder's state at SafeBind? |
|---|---|---|
| 200 | `ok` | no |
| 403 revoked; KMS `AccessDenied` | `publisher_revoked` | that purpose only |
| 404 unknown_kid; KMS `NotFoundException` | `unknown_kid` | no |
| 410; `/health` destroyed; KMS `PendingDeletion`/`Disabled` | `key_destroyed` | yes → confirmed gone (authoritative) |
| timeout, network error, 5xx, 429, 401, 503; KMS throttling, `Unavailable`, `Updating`, `Creating` | `publisher_unavailable` | active → unavailable only, never further |
| 400 bad_wrap / cert_mismatch | `bad_wrap` / `cert_mismatch` | no |

A timeout is never evidence that a key is gone. While a holder is unavailable SafeBind keeps serving the
cached public key, so capture continues and unwraps wait.

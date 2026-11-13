# OSIR Desktop Session v1

Scope: native Desktop only; Web cookie sessions and the legacy 300-second
`/api/v2/auth/osir/exchange` remain unchanged. This contract does not yet accept
Client handoff assertions (their receiver/PKCE verification is a separate feature).

All endpoints are POST JSON, no cookies, redirects, query credentials or response
caching. Unknown/duplicate fields and bodies over 12 KiB are rejected. Desktop
assertions use the existing verified `osir-anywhere-login+jwt` and exact
`client_id=osir-anywhere-desktop`; Web assertions and source Client tokens fail.

| Path under `/api/v2/auth/osir/desktop` | Request | Success |
| --- | --- | --- |
| `/exchange` | `{assertion:string}` | session JSON below |
| `/refresh` | `{refreshToken:string}` | rotated session JSON below |
| `/logout` | `{refreshToken:string}` | 204, idempotent for unknown/expired/spent tokens |

```json
{
  "accessToken": "<signed access>",
  "tokenType": "Bearer",
  "expiresIn": 300,
  "refreshToken": "<32 random/derived bytes, base64url, 43 chars>",
  "refreshExpiresIn": 604800,
  "identity": {"issuer":"https://osirclaw.com","subject":"<decimal OSIR sub>","userId":"<Anywhere user>"}
}
```

`refreshExpiresIn` decreases to the original seven-day absolute deadline; refresh
never extends it. Access has dedicated claims `aud=osir-anywhere-desktop` and
`token_use=desktop-access`, plus `auth=osir`, sub, sid, exp. Desktop registry keys
and refresh derivation have separate namespaces; Web and Desktop refresh tokens
and sid families cannot be used interchangeably. Bearer access is accepted by
Anywhere user transports only with a live matching desktop registry and account.

Redis stores only refresh hashes and nonsecret identity metadata. WATCH/MULTI
rotation is atomic. A five-second recovery window returns the same successor
for duplicate refresh attempts; it never chains a second rotation within that
window. Spent refresh hashes remain indexed until the absolute deadline. Reuse
outside the window revokes the entire sid, including already issued access.
Redis outages fail closed. Disabled/deleted users cannot refresh. Logout with a
known spent token also revokes its sid. Logout on dependency failure is 503.

Main owns refresh exclusively. OSIR API grants remain temporary and are revoked
after assertion exchange. Main persists only safeStorage encrypted
ciphertext in a private atomic file; unavailable encryption (including Linux
`basic_text` fallback) is an error, never a plaintext downgrade. Renderer receives
only accessToken/server/expiresIn via IPC, never refresh/identity secrets or
storage paths; access is held in memory, not localStorage. Main refresh is single
flight; cancellation/logout invalidates late responses. On startup Main refreshes
the stored session. Renderer renews access ahead of expiry and on visibility.

Logout cancels OAuth/refresh, clears local active session, and stops the managed
Connector before completing. If remote revocation fails, an encrypted pending
revocation is retried on next restore or before a new browser login in the same
process, always against the origin saved with that refresh (never a newly selected
server). Only an unredirected HTTP 204 acknowledges logout; gateway 401/403,
other 2xx or 5xx retain the pending record. Refresh 401/403 still invalidates the
active local session. A pending logout blocks accepting a new session until revocation succeeds
or its absolute deadline expires; UI reports pending, not global revocation.
OAuth retains cleanup ownership as soon as Desktop exchange issues credentials,
before awaiting temporary OSIR-grant logout. Cancellation/shutdown or a failed/
unaccepted Main callback revokes that issued Desktop session using an independent
bounded request. Failed revocation is retained in a separate safeStorage encrypted
queue, without overwriting an existing active session or pending logout. The queue
is drained on restore and login before further authorization. If encryption and
network both fail, cleanup fails closed and retains a memory retry only; there is
no durable guarantee across process loss when system encryption is unavailable.
Device credentials are not deleted/revoked by account logout. OSIR API logout is
not an instantaneous cross-product revocation guarantee.

Account login/recovery and skipping onboarding never provision, reconnect or
start a local Connector. They may read the saved owner/origin binding. A separate
explicit user action grants local-device connectivity. Desktop's backend launch
snapshot sets `requireExplicitConnection=true` so old autostart settings cannot
bypass that decision after an app restart. This is a consent boundary, not a file
system sandbox; selecting a working directory does not isolate Agent access.

Errors expose fixed local messages only (400/415/422 malformed request, 401
invalid/expired/replayed, 403 disabled, 404 auth disabled, 503 dependency outage).
Do not forward provider bodies, URLs, assertion/token strings or raw exceptions.

Integration ownership: this slice implements server session lifecycle, Main
secure storage/coordinator, OAuth adaptation, IPC and renderer recovery/logout.
The primary agent owns build default addresses, packaging scripts, CHANGELOG and
real installed-app verification. No cloud deployment is included.

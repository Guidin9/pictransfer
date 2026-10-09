# Spike C — hibernating Durable Object WebSocket

Throwaway experiment for `docs/spikes.md` § Spike C (C1–C4). It informs the
keepalive interval `K` in `docs/protocol.md` §6.3 and the cost claims in ADR 0004.

- `src/index.ts` — Worker + one SQLite-backed Durable Object (`KeepaliveHub`).
  `GET /ws?label=<x>` upgrades into the single instance `getByName("spike")`.
  The object accepts with `ctx.acceptWebSocket(server, [label])` (Hibernation
  API) and sets `ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("p", "o"))`,
  so a `p` frame is answered with `o` by the runtime without waking the object.
  It logs counts and close codes only.
- `wrangler.jsonc` — Worker `warpshot-spike-keepalive`, `new_sqlite_classes`
  migration. **No `account_id`** (ADR 0007): wrangler uses the logged-in account.
- `client.mjs` — Node (built-in `WebSocket`) client holding 6 sockets with
  ping intervals 30 / 60 / 90 / 120 / 300 / 600 s (labels `k30` … `k600`).

## Deploy

```powershell
cd spikes\do-keepalive
npm install --prefer-offline --no-audit --no-fund --ignore-scripts
npx tsc --noEmit
npx wrangler login            # once
npx wrangler deploy
```

The deploy prints the `https://warpshot-spike-keepalive.<subdomain>.workers.dev`
URL. **Do not write it into any file in the repo.** To see it again: dashboard →
*Workers & Pages* → `warpshot-spike-keepalive` → *Settings → Domains & Routes*,
or re-run `npx wrangler deploy` (idempotent; prints the URL).
`npx wrangler deployments list` shows the deployed versions only. Note: on an
account without a workers.dev subdomain, a non-interactive `wrangler deploy`
registers one automatically, named after the `package.json` `name` (change it in
the dashboard: *Workers & Pages → Account details → Subdomain*).

Tear down after the spike: `npx wrangler delete warpshot-spike-keepalive`.

## Run

The URL is passed only through the environment:

```powershell
cd spikes\do-keepalive
$env:SPIKE_URL = "https://warpshot-spike-keepalive.<subdomain>.workers.dev"
# detached 6-hour run, survives the terminal:
Start-Process node -ArgumentList "client.mjs" -WindowStyle Minimized `
  -RedirectStandardOutput out\client-stdout.log -RedirectStandardError out\client-stderr.log
```

Options (env): `SPIKE_DURATION_S` (default 21600 = 6 h), `SPIKE_PONG_TIMEOUT_S`
(default 15). `Ctrl+C` / `Stop-Process` (SIGINT/SIGTERM where delivered) writes
the summary early; a hard kill does not, but the JSONL log is always complete.

Keep the PC awake for the run (no sleep/hibernate), otherwise C1 measures the
laptop, not Cloudflare. A `stall` event marks a timer that fired > 5 s late,
i.e. the process or PC was suspended.

## Output (`out/`, git-ignored)

- `run-<timestamp>.jsonl` — one line per event:
  `{t, label, event, code?, reason?, rtt_ms?, lived_s?, expected?, never_opened?, client_initiated?}`
  with `event` ∈ `start | open | pong | missed | close | error | stall | stop`.
  - `missed`: no `o` within the pong timeout (or before the next ping). After 2
    consecutive misses the client closes with 4000 and reconnects (protocol §6.3);
    that close is counted as `client_forced_closes`, not as unexpected.
  - every close is followed by a reconnect after 1 s.
- `summary-<timestamp>.json` — per label: `opens`, `connect_failures`, `closes`,
  `unexpected_closes`, `client_forced_closes`, `missed_pongs`, `errors`,
  `stalls`, `close_codes`, `longest_uninterrupted_s`, `max_rtt_ms`.

Quick look while it runs:

```powershell
Get-Content out\run-*.jsonl -Tail 20
Select-String -Path out\run-*.jsonl -Pattern '"event":"(close|missed|stall)"'
```

## Reading the results

**C1 — longest interval with zero unexpected closes.** From the summary: the
largest `interval_s` whose `unexpected_closes == 0` and `missed_pongs == 0`
(and `stalls == 0`). Expected: Cloudflare closes idle WebSockets after ~100 s
without traffic in either direction, so `k120` and above should show periodic
closes (look at `lived_s` and `code`, typically 1006) while `k30`/`k60` stay up.
Pass: ≥ 60 s.

**C2 — DO duration while idle.** Dashboard: *Workers & Pages → Durable Objects*
→ namespace `warpshot-spike-keepalive_KeepaliveHub` → **Metrics** tab (default
window 24 h; can filter by object name `spike`). Read *Duration / Wall time*
and *Active time* over the run: with hibernation and only auto-responses it
should be ≈ 0 apart from short spikes at each (re)connect.
GraphQL (`https://api.cloudflare.com/client/v4/graphql`, an API token with
*Account Analytics: Read* — keep it in an env var, never in a file):

```graphql
query ($account: String!, $start: Date!, $end: Date!) {
  viewer {
    accounts(filter: { accountTag: $account }) {
      durableObjectsInvocationsAdaptiveGroups(
        filter: { date_geq: $start, date_leq: $end }, limit: 100) {
        sum { requests }
        dimensions { date }
      }
      durableObjectsPeriodicGroups(
        filter: { date_geq: $start, date_leq: $end }, limit: 100) {
        sum { cpuTime activeTime inboundWebsocketMsgCount outboundWebsocketMsgCount }
        max { activeWebsocketConnections }
        dimensions { date }
      }
    }
  }
}
```

Field names other than `requests` and `cpuTime` are not in the docs example;
confirm them with GraphQL introspection
(https://developers.cloudflare.com/analytics/graphql-api/features/discovery/introspection/)
before relying on them. Docs:
https://developers.cloudflare.com/durable-objects/observability/metrics-and-analytics/
— "with WebSocket Hibernation, incoming WebSocket messages are represented in
`durableObjectsInvocationsAdaptiveGroups`" rather than the periodic dataset.

**C3 — requests per connection-day (are auto-responses billed?).** Compare
`durableObjectsInvocationsAdaptiveGroups.sum.requests` for the run window with
what the client sent (count `pong` + `missed` lines = pings, plus `open` lines =
upgrades). If `requests ≈ opens`, auto-responses are not counted; if
`requests ≈ opens + pings`, they are. Also check the account's *Workers & Pages →
Plans / Usage* page for the daily DO request count.

What the docs say (https://developers.cloudflare.com/durable-objects/platform/pricing/,
read 2026-10-09):

- "A request is needed to create a WebSocket connection. There is no charge for
  outgoing WebSocket messages, nor for incoming WebSocket protocol pings. For
  compute requests billing-only, a 20:1 ratio is applied to incoming WebSocket
  messages … The 20:1 ratio does not affect Durable Object metrics and
  analytics, which reflect actual usage."
- "Application level auto-response messages handled by
  state.setWebSocketAutoResponse() will not incur additional wall-clock time,
  and so they will not be charged."
- Free tier: 100,000 requests/day (HTTP requests, RPC sessions, WebSocket
  messages, alarm invocations) and 13,000 GB-s/day duration.
- https://developers.cloudflare.com/durable-objects/api/state/ : "the
  auto-response will be returned without waking WebSockets in hibernation and
  incurring billable duration charges."

So duration is clearly not charged; whether an auto-responded `p` counts toward
the 100k/day request quota is not stated unambiguously — that is what C3
measures. Worst case at K = 60 s: 1440 messages/connection-day → 72 billable
requests at 20:1 (1000 devices ≈ 72k/day, under 100k) but 1440 raw messages if
the free-tier quota counts them 1:1 (only ~69 devices).

**C4 — reconnect after sleep/resume and network change.** Not automated here:
during or after the run, sleep the laptop / toggle Wi-Fi and read the time
between the `stall`/`close` line and the next `open` for each label (the client
reconnects after 1 s; the agent will also reconnect on OS resume/network events).

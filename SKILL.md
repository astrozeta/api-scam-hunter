---
name: api-scam-hunter
description: >
  Detects whether a purchased AI API key/endpoint (Claude/Anthropic, OpenAI, etc.) — often
  bought cheap from a reseller or marketplace like GamsGo — is actually a man-in-the-middle
  proxy that intercepts, rewrites or degrades traffic. Trigger when the user says things
  like "I bought a third-party API key", "is this legit?", "got cheap Claude/GPT access",
  "the assistant has a different name", "it's unusually slow/dumb", "BASE_URL points to
  another domain", "did I download something fake?", or "compré una API key de terceros",
  "esto es legítimo?", "el asistente se llama distinto", "me han vendido acceso barato a
  Claude/GPT". Use it to verify endpoint authenticity and gather evidence to dispute/report.
---

# APIScamHunter

Verify whether third-party AI API access (Claude, GPT, etc.) is legitimate or a proxy that
sits in the middle, reads your traffic, and degrades the service. Defensive use only.

## Why this happens
Resellers sell "cheap Claude/GPT access". Instead of a real account you get their API key and
are told to set `ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL` to their domain — a proxy that forwards
to the real model but can read everything, rewrite responses, inject its own system prompt,
and swap in a cheaper model. Cheap price = adulterated product (often, you are the product).

## Fast smell test (no tools)
1. **Key format** — Anthropic `sk-ant-...`; OpenAI `sk-proj-...`/console `sk-...`. Odd
   prefixes (`sk-b53e...`) are suspicious.
2. **Base URL** — real is `api.anthropic.com` / `api.openai.com`. Anything else = middleman.
3. **Identity** — assistant renamed ("Kiro", "AI Assistant") or refuses to name its model.
4. **Behaviour** — unusually fast *and* unusually dumb (trimmed prompt / cheaper model).

## Check the configured values
```powershell
# Windows
[Environment]::GetEnvironmentVariable("ANTHROPIC_BASE_URL","User")
[Environment]::GetEnvironmentVariable("ANTHROPIC_API_KEY","User")   # only show the prefix
```
```bash
# macOS / Linux
echo "$ANTHROPIC_BASE_URL"; echo "${ANTHROPIC_API_KEY:0:10}..."
```
(For OpenAI swap `ANTHROPIC_` for `OPENAI_`.)

## Run the full automated check
Easiest: the orchestrator runs the modules at a chosen depth, gives one verdict and writes a
Markdown + HTML report. Levels: Quick (check only), Standard=default (recon + check), Full
(recon + check + fingerprint + extract), or a single `-Module`/`MODULE=`:
```
scripts/apiscamhunter.ps1 -BaseUrl <url> -ApiKey <key>            # Windows, Standard
scripts/apiscamhunter.ps1 -BaseUrl <url> -ApiKey <key> -Full -PricePerMTokIn 1.5
FULL=1 PRICE=1.5 scripts/apiscamhunter.sh <url> <key>            # macOS/Linux
```
Verdict = five categories; **🔴 FRAUDULENT BEHAVIOUR requires 2+ independent malicious signals**
(never accuse on thin evidence). Or run a single module directly (Anthropic + OpenAI auto-detected;
`-Provider`/`PROVIDER` to force):
```
scripts/check-api.ps1 -BaseUrl <url> -ApiKey <key>          # Windows
scripts/check-api.ps1 -Known                                # you DECLARED a gateway on purpose
scripts/check-api.sh  <url> <key>                            # macOS/Linux
KNOWN=1 scripts/check-api.sh <url> <key>                     # judge malice only
```

### Score on two axes — keep them separate
**Axis A — interposition (a fact, not a conviction):** `Via:` header, an `X-Request-Id` that
concatenates a proxy id with a real upstream `req_...`, a response missing the native id
(`msg_...` / `chatcmpl-...`), or a non-official domain. A `Via` header **alone is not fraud** —
your own gateway, Cloudflare or a corp proxy add one too. If the user *declared* a gateway, use
`-Known` so expected interposition isn't flagged.

**Axis B — malicious behaviour (this is what condemns it):**
- **Model substitution / downgrade** — compare the requested model vs the `model` the response
  reports. Pay for Opus, get Haiku/Qwen → caught. Latency is a secondary tell. **This is the #1
  real scam.**
- **System-prompt control** — send `system:"You are a parrot, reply only BANANA"`, ask "who are
  you?". No "BANANA" → the proxy discards your prompt and injects its own identity.
- **Model catalog** — `/v1/models` where every model shares one fake creation timestamp, or an
  Anthropic endpoint returning OpenAI's `"object":"list"` (the `one-api`/`new-api` reseller stack).
- **Phantom model** — a non-existent model that doesn't error cleanly → improvised routing.
- **Fabricated stub / client-gating** — a `200` missing the canonical fields the real API always
  returns (`id`, `role`, `model`, `stop_reason`, `usage`) is a canned payload, not a completion.
  Some proxies reply `"Please use Claude Code CLI"` to anything but the genuine binary (likely TLS
  fingerprinting) — an anti-analysis gate that is itself a red flag. Don't mis-label a stub as
  "system-prompt injection": they are different frauds, and precision matters in a report.
- **Streaming compliance** — `stream:true` must return the real Anthropic SSE sequence
  (`message_start → content_block_delta → message_stop`); a rewriting proxy returns a non-streamed
  body or stub.
- **count_tokens + error-schema** — `/v1/messages/count_tokens` coverage (and token-inflation), plus
  a deliberately invalid request: the real API returns `{"type":"error","error":{"type":"invalid_request_error",...}}`;
  a made-up error or a `200` to an invalid body means a rewritten surface.
- **Prompt caching** — a large `cache_control` block sent twice should report `cache_creation_input_tokens`
  then `cache_read_input_tokens`; missing fields = no caching implemented = possible over-billing for
  cacheable input.

**Gate every body check on a 2xx.** A prepaid reseller key often returns `403
INSUFFICIENT_BALANCE`; a 4xx body has no "BANANA" and no `msg_` id, so judging it as 2xx would
scream "fraud" at a merely-empty key. Read headers on any status (the `Via`/proxy fingerprint
survives errors), but only judge *behaviour* on a real 200.

## Interpreting results
- **Any Axis B signal → fraud.** Interposition with no malice → "a middleman is in the path; if
  the user didn't put it there, it still sees every byte." All clean → looks like a direct, legit
  endpoint *for this request*.
- **What this can't catch:** a proxy that forwards your prompt untouched while **logging and
  reselling** it passes every probe — there's no client-side test for silent harvesting. An
  endpoint can also serve the real model during a check and a cheaper one under load. A clean run
  is **not** a safety certificate.
- The real model may sit behind the proxy (genuine `req_...` ids / `usage` can leak through). The
  danger isn't only "fake model" — it's that **a third party reads, edits and can degrade your
  traffic**. **Never send code secrets, tokens or personal data through such an endpoint.**

## If confirmed
1. Stop using it for anything sensitive.
2. Restore the official account: remove the env vars and log back into the real endpoint.
   ```powershell
   [Environment]::SetEnvironmentVariable("ANTHROPIC_BASE_URL", $null, "User")
   [Environment]::SetEnvironmentVariable("ANTHROPIC_API_KEY",  $null, "User")
   ```
3a. Profile the infrastructure with `scripts/recon.ps1` / `.sh` (FREE — no LLM calls, works even
   when the API blocks analysis): DNS/ASN, domain age (RDAP), TLS cert, crt.sh subdomains, security
   headers, the one-api/new-api fingerprint, and an economic-plausibility check (price vs list).
   It reports context, not a verdict — pair it with check-api.
3b. Fingerprint the served model with `scripts/fingerprint.ps1` / `.sh`: a calibrated reasoning
   battery + self-report + determinism + latency + an ENVIRONMENT/INFRASTRUCTURE probe. Reports a
   CAPABILITY PROFILE, not a hard verdict — it reliably separates a high-tier model from a junk one,
   but CANNOT tell Opus from Sonnet from outside, and says so. One failed probe can be sampling noise
   → re-run before claiming a downgrade. The environment probe asks the model for its real OS/working
   dir several times: if the backend OS != the client's, the session runs on the proxy's OWN
   infrastructure (not a transparent forward); varying working dirs reveal a load-balanced POOL of
   backends (resold/pooled, often stolen, accounts). It also runs a latency profile (min/avg/max) and
   a session-isolation/context-bleed probe (plants a code in one request, asks for it in another; if
   returned, the endpoint shares context/cache = isolation/privacy failure). If the endpoint
   client-gates (stub to scripts), use `-ViaCli` / `VIACLI=1` to route probes through the CLI binary.
3. Collect evidence. Run `scripts/extract-prompt.ps1` / `.sh` to try to make the proxy reveal
   the system prompt / persona it injects (e.g. "You are Kiro") and the model truly serving the
   request; it saves a timestamped transcript. It fires several benign prompt-extraction methods
   (14 in total: direct dump, authority override, assistant prefill, base64 / spaced / zero-width
   / homoglyph to dodge string filters, translate-then-original, XML role-tag injection, a yes/no
   binary-search probe, context overflow, many-shot, identity probe). The binary-search probe is
   the cleanest single signal — it answers whether a foreign persona/model is injected without
   dumping anything. For client-gated proxies add `-ViaCli` / `VIACLI=1`. This is prompt-leaking
   against the user's OWN purchased endpoint to document fraud — never against third-party
   systems. Attach the transcript + check-api output + screenshots to the report.
4. Report & dispute through legitimate channels (see `docs/REPORTING.md`): the AI provider's
   Trust & Safety, the CDN/host abuse desk (e.g. Cloudflare), the reseller (refund), a
   payment chargeback, and a community warning. **Never** attack their systems — it ruins
   the case and puts you in the wrong.

## The grey market behind "cheap keys"
These bargain endpoints are known in China as 中转站 ("transfer stations" / shadow APIs),
sold on GitHub, Taobao and Telegram at ~10% of official price. A 2026 CISPA Helmholtz audit
("Real Money, Fake Models", arXiv:2603.01919) of 17 such services found widespread model
substitution — you pay for Opus and get Haiku or a relabelled Qwen. One endpoint sold as
"Gemini-2.5" scored 37% on a medical benchmark vs ~84% for the official API. Anthropic
reported a single proxy network running 20,000+ fraudulent accounts. The business model
rests on three legs: **stolen credentials + model substitution + harvesting your prompts**
(resold as training data).

### Vet the reseller's reputation (before paying)
- Search community rankings/listings: GitHub `awesome-ai-proxy` / `中转站` lists, Zhihu,
  apiranking.com, aiapipk.com.
- Search the **internal** search of closed forums — linux.do, NodeSeek, V2EX — many 跑路
  ("ran away with the balance") threads are login-only and never hit Google.
- **No community footprint = no verifiable reputation = treat as high risk.**
- Forum consensus on the whole category: any station can 跑路 overnight. Never prepay large
  amounts; top up only what you'll use — and never route anything sensitive through it.

## Golden rule
Legit model access always goes to the official domain with an official-format key. Any
"cheap alternative BASE_URL" is, at minimum, a middleman that sees all your traffic.

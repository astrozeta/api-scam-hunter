---
name: ai-api-scam-detector
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

# AI API Scam Detector

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
Prefer the bundled scripts — they run all probes and print a verdict:
```
scripts/check-api.ps1 -BaseUrl <url> -ApiKey <key>     # Windows
scripts/check-api.sh  <url> <key>                       # macOS/Linux
```

### What each probe means
- **Headers** — `Via:` header, an `X-Request-Id` that concatenates a proxy id with a real
  upstream `req_...` id, or a response body missing the `"id":"msg_..."` field → an
  interposed proxy that rewrites responses.
- **System-prompt injection** — send `system:"You are a parrot, reply only BANANA"` and ask
  "who are you?". If you don't get "BANANA", the proxy discards your system prompt and
  imposes its own. **Most conclusive test.**
- **Model catalog** — `/v1/models` where every model shares one fake `created_at` (e.g.
  `2024-01-01T00:00:00Z`), or mixes another vendor's fields (`"object":"list"` is OpenAI,
  not Anthropic) → fabricated catalog. Bonus: advertised models that 503 when used.
- **Phantom model** — request a non-existent model; if it doesn't error cleanly, routing is
  improvised.

## Interpreting results
- The real model may sit behind the proxy (genuine `req_...` ids / `usage` schema can leak
  through). The danger isn't only "fake model" — it's that **a third party reads, edits and
  degrades your traffic**, with no guarantee they keep serving the real model. **Never send
  code secrets, tokens or personal data through such an endpoint.**

## If confirmed
1. Stop using it for anything sensitive.
2. Restore the official account: remove the env vars and log back into the real endpoint.
   ```powershell
   [Environment]::SetEnvironmentVariable("ANTHROPIC_BASE_URL", $null, "User")
   [Environment]::SetEnvironmentVariable("ANTHROPIC_API_KEY",  $null, "User")
   ```
3. Collect evidence (script output + screenshots).
4. Report & dispute through legitimate channels (see `docs/REPORTING.md`): the AI provider's
   Trust & Safety, the CDN/host abuse desk (e.g. Cloudflare), the reseller (refund), a
   payment chargeback, and a community warning. **Never** attack their systems — it ruins
   the case and puts you in the wrong.

## Golden rule
Legit model access always goes to the official domain with an official-format key. Any
"cheap alternative BASE_URL" is, at minimum, a middleman that sees all your traffic.

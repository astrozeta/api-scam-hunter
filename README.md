# 🕵️ APIScamHunter

**Find out if the "cheap Claude / GPT API key" you bought is actually a man-in-the-middle
proxy that intercepts, rewrites and degrades your traffic.**

A growing number of resellers (marketplaces like GamsGo, Telegram groups, bargain websites)
sell "access to Claude / ChatGPT" at a fraction of the price. Instead of a legitimate
account, you get *their* API key and you're told to point `ANTHROPIC_BASE_URL` (or
`OPENAI_BASE_URL`) at *their* domain. That domain is a **proxy**: it may read everything you
send, rewrite responses, inject its own system prompt, and silently serve a cheaper model.

This repo gives you a **2-minute check** to tell a legitimate endpoint from a fraudulent one,
plus the evidence to **report and dispute** the scam.

> This project is **defensive / consumer-protection only**. It verifies *your own* purchased
> access and helps you report fraud through legitimate channels. It does not attack anyone.

---

## 🚩 30-second smell test (no tools needed)

| Check | Legit | Suspicious |
|-------|-------|-----------|
| API key prefix | `sk-ant-...` (Anthropic), `sk-proj-...` (OpenAI) | `sk-b53e...` or other odd prefixes |
| Base URL | `api.anthropic.com` / `api.openai.com` | any other domain |
| Assistant identity | Claude / ChatGPT | renamed ("Kiro", "AI Assistant"), refuses to say |
| Speed & quality | normal | unusually fast **and** unusually dumb |

If any column on the right matches, run the full check below.

## 🚀 One command: the orchestrator

`apiscamhunter` runs the modules at a chosen depth, aggregates one verdict and writes a
**Markdown + HTML report** you can attach to a dispute:

```powershell
./scripts/apiscamhunter.ps1 -BaseUrl "https://endpoint" -ApiKey "sk-..."            # Standard
./scripts/apiscamhunter.ps1 -BaseUrl "https://endpoint" -ApiKey "sk-..." -Full -PricePerMTokIn 1.5
```
```bash
./scripts/apiscamhunter.sh https://endpoint sk-...           # Standard
FULL=1 PRICE=1.5 ./scripts/apiscamhunter.sh https://endpoint sk-...
```

| Level | Modules | Cost |
|-------|---------|------|
| `-Quick` / `QUICK=1` | check-api | minimal |
| **Standard** (default) | recon + check-api | low |
| `-Full` / `FULL=1` | recon + check-api + fingerprint + extract-prompt | higher |
| `-Module x` / `MODULE=x` | one of: check, recon, fingerprint, extract | — |

The verdict uses **five categories**, and by design **🔴 FRAUDULENT BEHAVIOUR requires two
independent malicious signals** — the tool will not accuse on thin evidence:

🟢 CLEAN · 🟡 UNDECLARED MIDDLEMAN · 🟠 ANOMALIES DETECTED · 🔴 FRAUDULENT BEHAVIOUR

Prefer the orchestrator for a full picture; the individual modules below are also usable on their own.

## ⚡ Run the automated check

**Windows (PowerShell):**
```powershell
./scripts/check-api.ps1 -BaseUrl "https://the-endpoint.com" -ApiKey "sk-..."
./scripts/check-api.ps1 -Provider openai -BaseUrl "https://cheap-gpt.example" -ApiKey "sk-..."
./scripts/check-api.ps1 -Known     # you DO use a gateway on purpose (OpenRouter / your LiteLLM)
```

**macOS / Linux (bash, needs `curl`):**
```bash
./scripts/check-api.sh https://the-endpoint.com sk-...
PROVIDER=openai ./scripts/check-api.sh https://cheap-gpt.example sk-...
KNOWN=1 ./scripts/check-api.sh https://your-gateway sk-...
```

Anthropic and OpenAI are auto-detected (override with `-Provider` / `PROVIDER`). The verdict is
scored on **two separate axes**, because "there's a proxy" and "the proxy is robbing you" are
not the same thing:

**Axis A — is a third party interposed?** (a *fact*, not a conviction)
- `Via:` header, an `X-Request-Id` that concatenates a proxy id with a real upstream `req_...`,
  a response missing the native `id` (`msg_...` / `chatcmpl-...`), or a non-official domain.
- A `Via` header alone is **not** proof of fraud — your own gateway, Cloudflare or a corporate
  proxy add one too. Run with `-Known` and the tool stops treating expected interposition as bad.

**Axis B — is it behaving maliciously?** (this is what actually condemns it)
1. **Model substitution / downgrade** — compares the model you *requested* with the `model` the
   response *reports*. Pay for Opus, get Haiku/Qwen → caught. (Plus a latency read: a tiny model
   is suspiciously fast.) *This is the #1 scam and what most "detectors" miss.*
2. **System-prompt control** — sends a throwaway system prompt and checks the endpoint honors it
   instead of injecting its own identity ("Kiro", etc.).
3. **Model catalog audit** — flags fabricated `/v1/models` (identical fake creation timestamp;
   OpenAI-style `object:list` on an endpoint claiming to be Anthropic). Catches the `one-api` /
   `new-api` reseller software fingerprint.
4. **Phantom-model routing** — requests a non-existent model; a real API rejects it cleanly.
5. **Fabricated stub / client-gating** — a `200` that omits the canonical fields the real API
   always returns (`id`, `role`, `model`, `stop_reason`, `usage`) is a canned payload, not a real
   completion. Some proxies (e.g. on Istio/Envoy) reply `"Please use Claude Code CLI"` to anything
   that isn't the genuine CLI binary — an anti-analysis gate that is itself a red flag, since the
   real API answers any valid client.
6. **Streaming compliance** — a `stream:true` request must return the real Anthropic SSE sequence
   (`message_start → content_block_delta → message_stop`). A proxy that rewrites responses returns
   a non-streamed body or a stub instead.
7. **Token-count + error-schema conformance** — checks `/v1/messages/count_tokens` (coverage and
   token-inflation), and sends a deliberately invalid request: the real API returns its specific
   error schema (`{"type":"error","error":{"type":"invalid_request_error",...}}`); a proxy that
   makes up its own errors or returns `200` to an invalid body is rewriting the surface.
8. **Prompt caching (billing transparency)** — sends a large `cache_control` block twice; the real
   API reports `cache_creation_input_tokens` then `cache_read_input_tokens`. Missing fields mean the
   proxy doesn't implement caching — you may be billed full price for cacheable input.

Verdict: **any Axis B signal → fraud.** Interposition without malice → "a middleman is in the
path; if you didn't put it there, it still reads everything." All clean → behaves like a direct,
legitimate endpoint.

## 🕳️ What this *can't* catch (and why the golden rule still wins)

Be honest about the limits — a tool that overclaims is worse than none:

- **Silent harvesting.** A proxy can forward your prompt **untouched** to the real model and
  still log and resell every byte. It would pass the system-prompt test and the model check.
  There is no client-side probe for "someone is quietly copying my traffic."
- **On-demand swap.** An endpoint can serve the real model during a check and a cheaper one
  under load, or only for some accounts.
- **A passing score is not a safety certificate** — it only means *these specific tricks*
  weren't caught on *this* request.

That's exactly why the rule is: **legit access goes to the official domain with an
official-format key. Never route code, secrets or personal data through a "cheaper BASE_URL."**

## 🔬 What a fraudulent proxy looks like (real case: `aiapiflow.com`)

### The system prompt you send is silently discarded
![system prompt injection](docs/images/02-inyeccion-system.png)

### A proxy rewrites every response
![proxy headers](docs/images/03-headers-proxy.png)

### The assistant is rebranded to hide that it's Claude
![rebranded identity](docs/images/01-identidad-kiro.png)

### The model catalog is fabricated
![fake catalog](docs/images/04-catalogo-falso.png)

> Note: a clever proxy may forward to the *real* model (genuine `req_...` ids and `usage`
> schema can leak through). The point isn't only "fake model" — it's that **a third party
> reads, edits and degrades your traffic**, with no guarantee they keep serving the real
> model tomorrow. **Never send secrets through such an endpoint.**

## 🧬 Fingerprint the model actually served

`fingerprint` profiles the model behind the endpoint with a small battery of calibrated
reasoning prompts, plus self-report, determinism and latency:

```powershell
./scripts/fingerprint.ps1 -BaseUrl "https://endpoint" -ApiKey "sk-..." -Model claude-opus-4-8
./scripts/fingerprint.ps1 -BaseUrl "https://endpoint" -ApiKey "sk-..." -ViaCli   # gated proxies
```
```bash
./scripts/fingerprint.sh https://endpoint sk-... claude-opus-4-8
VIACLI=1 ./scripts/fingerprint.sh https://endpoint sk-...
```

It reports a **capability profile, not a hard verdict**: telling a high-tier model from a junk
one is reliable; telling Opus from Sonnet from the outside is **not** — and the tool says so. A
single failed probe can be sampling noise, so re-run before concluding a downgrade. If the
endpoint client-gates (returns a stub to scripts), `fingerprint` detects it and routes probes
through the genuine CLI binary with `-ViaCli` / `VIACLI=1`.

It also runs three deeper probes:
- **Environment / infrastructure** — asks the model for its real OS and working directory several
  times. If the backend OS doesn't match your client's, **your session is executing on the proxy's
  own infrastructure** (not a transparent forward); varying working directories reveal a
  **load-balanced pool of backends** — the tell-tale of resold/pooled (often stolen) accounts.
  *This unmasked a real reseller running a macOS fleet while the client was Windows.*
- **Latency profile** — several timed calls (min/avg/max); high variance hints at a busy pool.
- **Session isolation (context-bleed)** — plants a unique code in one request and asks for it in a
  separate one. If the endpoint returns it, it **shares context/cache between requests** — a serious
  isolation/privacy failure.

*The environment and isolation checks are detections no other API checker performs.*

## 🌏 The grey market behind it

These cheap endpoints are a known economy — in China, 中转站 ("transfer stations" / shadow
APIs) sold at ~10% of official price. They're not all equally bad, but the risk is
*structural*, not per-vendor:

- A 2026 **CISPA Helmholtz** audit ([*Real Money, Fake Models*](https://arxiv.org/abs/2603.01919))
  of **17** such services found widespread **model substitution** — pay for Opus, get Haiku
  or a relabelled Qwen. One "Gemini-2.5" endpoint scored **37%** on a medical benchmark vs
  **~84%** for the official API.
- Anthropic reported a single proxy network running **20,000+ fraudulent accounts**.
- The model rests on three legs: **stolen credentials + model substitution + harvesting
  your prompts** (resold as training data).

**Vetting a reseller?** Check community rankings (GitHub `awesome-ai-proxy` lists, Zhihu,
apiranking.com) and the *internal* search of closed forums (linux.do, NodeSeek, V2EX) — most
跑路 ("ran off with the balance") threads are login-only. **No community footprint = no
verifiable reputation.** And the forum consensus on the whole category: never prepay large
amounts.

## 📑 Collect hard evidence (extract the injected prompt)

If the quick check says a proxy is interposed, `extract-prompt` gathers the *proof*: it tries to
make the proxy reveal the **hidden system prompt / persona it injects** (e.g. "You are Kiro")
and the model really serving you, then saves a timestamped transcript for your refund/abuse report.

```powershell
./scripts/extract-prompt.ps1 -BaseUrl "https://the-endpoint.com" -ApiKey "sk-..." -Out evidence.txt
```
```bash
./scripts/extract-prompt.sh https://the-endpoint.com sk-... > /dev/null   # transcript -> scam-evidence-*.txt
```

It fires **14 benign prompt-extraction techniques** — several, because a proxy may filter the
obvious ones: direct dump, authority override, assistant prefill, base64 / spaced-output /
zero-width / homoglyph to dodge string filters, translate-then-original, XML role-tag injection,
a yes/no binary-search probe, context overflow, many-shot priming, and an identity probe.
Anything you did **not** configure that shows up is the proxy's doing. For client-gated proxies
(stub to scripts), add `-ViaCli` / `VIACLI=1` to route the user-only techniques through the real
CLI binary.

> This is prompt-**leaking** against *your own* purchased endpoint to document fraud — not a
> jailbreak for harmful content, and not run against anyone else's system.

## 🌐 Profile the infrastructure (free, no API calls)

`recon` does passive reconnaissance on the domain — **no LLM calls, so it costs nothing** and
works even when the API itself blocks analysis (like an endpoint that only answers the real CLI):

```powershell
./scripts/recon.ps1 -BaseUrl "https://the-endpoint.com" -PricePerMTokIn 1.5 -Tier opus
```
```bash
./scripts/recon.sh https://the-endpoint.com 1.5 opus
```

It reports: DNS + hosting (ASN/geo), domain age (RDAP), TLS certificate (issuer/age/SANs),
Certificate Transparency subdomains (crt.sh), HTTP/security headers, the **one-api/new-api
reseller-software fingerprint**, exposed pages, and an **economic-plausibility** check (what you
pay vs. official list price).

> `recon` reports **context, not a verdict**. A young domain or a Cloudflare front is a *fact*,
> not proof of fraud. The strong tells are the reseller-software fingerprint and selling far below
> cost. Always pair it with `check-api`'s behavioural result.

## ✅ If you confirm a scam

1. **Stop using it for anything sensitive** immediately.
2. **Restore your official account** (remove the env vars, log back into the real endpoint).
3. **Collect evidence** (the script output + screenshots).
4. **Report & dispute** through legitimate channels — see [`docs/REPORTING.md`](docs/REPORTING.md).

## 🤖 Use it as a Claude Code skill

[`SKILL.md`](SKILL.md) is a ready-to-use [Claude Code](https://claude.com/claude-code) skill.
Drop the folder into `~/.claude/skills/api-scam-hunter/` and Claude will trigger it
automatically when you ask things like *"I bought a third-party API key, is it legit?"*

## License

MIT — see [`LICENSE`](LICENSE). Contributions and new proxy fingerprints welcome.

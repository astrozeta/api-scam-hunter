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
3. **Model catalog audit** — flags fabricated `/v1/models` (identical fake `created_at`;
   OpenAI-style `object:list` on an endpoint claiming to be Anthropic).
4. **Phantom-model routing** — requests a non-existent model; a real API rejects it cleanly.

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

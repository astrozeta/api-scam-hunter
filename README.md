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
```

**macOS / Linux (bash, needs `curl`):**
```bash
./scripts/check-api.sh https://the-endpoint.com sk-...
```

The script runs four probes and prints a verdict:
1. **Header inspection** — detects an interposed proxy (`Via:`, duplicated request-ids, a
   stripped message `id`).
2. **System-prompt injection test** — sends a throwaway system prompt and checks whether the
   endpoint honors it or overrides it with its own.
3. **Model catalog audit** — flags fabricated `/v1/models` listings (identical fake
   `created_at`, mismatched schema fields).
4. **Phantom-model routing** — requests a non-existent model to expose improvised routing.

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

# How to report & dispute a fraudulent AI API reseller

Once you've confirmed a proxy scam, hit it on **5 fronts at once**. Everything here is
legitimate — no hacking, no DoS. The strength of the case is that all of it is verifiable.

Have ready: the `check-api` script output, screenshots, and your proof of purchase.

## Front 1 — The AI provider (most effective)
They can cancel the upstream API account behind the proxy and act on trademark abuse.
- **Anthropic:** `usersafety@anthropic.com`, `security@anthropic.com`,
  https://support.anthropic.com (Trust & Safety / report abuse); trademark: `legal@anthropic.com`
- **OpenAI:** https://openai.com/policies report channels / `support@openai.com`
- Report: unauthorized API resale, traffic interception, brand impersonation, fake catalog.

## Front 2 — The CDN / host (takes down the front)
Most proxies hide behind a CDN. Find it: `nslookup <domain>` — Cloudflare ranges are
`172.67.x` / `104.21.x` and IPv6 `2606:4700::/32`.
- **Cloudflare abuse:** https://abuse.cloudflare.com (categories: phishing, fraud/scam,
  trademark/impersonation).

## Front 3 — The reseller / marketplace (refund + delisting)
- Open a refund ticket citing "product not as described".
- Attach evidence. The system-prompt-injection result is irrefutable: you don't control what
  you paid for.
- If refused, tell them you'll escalate to a payment chargeback and to the AI provider.

## Front 4 — Your payment method (chargeback)
- **Card:** request a chargeback for "non-conforming / fraudulent service".
- **PayPal:** open a dispute ("item not as described").
- Mind the deadline (often 60–120 days). Don't wait too long.

## Front 5 — Community warning (cuts their victim supply)
- Where: relevant subreddits (r/ClaudeAI, r/LocalLLaMA), Telegram/Discord groups, the
  marketplace reviews, Trustpilot.
- Post a short, factual summary + how to reproduce with `check-api`. Let the evidence talk.

## Suggested timeline
| Day | Action |
|-----|--------|
| 0 | Provider (F1) + CDN (F2) + open reseller ticket (F3) |
| +3 | If no refund → chargeback (F4) |
| +5 | Community warning (F5) with the case documented |

## Report template (adapt)
> Subject: Fraudulent resale of the [Anthropic/OpenAI] API — domain <proxy-domain>
>
> I purchased "access to [Claude/GPT]" via [reseller]. In reality I received an API key
> (prefix <prefix>) routing all traffic to <proxy-domain>, a proxy (server <stack> behind
> <CDN>) that: (1) intercepts and rewrites responses, (2) ignores the client system prompt
> and imposes its own, presenting the assistant as "<fake name>", (3) serves a fabricated
> model catalog, and (4) exposes user data to a third party. Reproducible technical evidence
> and proof of purchase attached. I request [refund / suspension / investigation].

## Do NOT
- Don't hack, flood (DoS) or access their systems.
- Don't publish your full API key or personal data in public warnings.

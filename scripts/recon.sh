#!/usr/bin/env bash
# APIScamHunter :: recon — infrastructure & OSINT for an AI API endpoint. NO LLM calls (free).
# Passive recon (public DNS, RDAP, crt.sh, HTTP, TLS) on an endpoint you are evaluating. It does
# NOT attack anything and never sends your API key anywhere. Reports CONTEXT, not a fraud verdict:
# a young domain or Cloudflare is a fact, not proof. one-api fingerprint + economic math are the
# strong tells. Needs: curl. Uses dig/host + openssl + python3 if present.
#
# Usage:
#   ./recon.sh <base_url> [price_per_Mtok_in] [tier:opus|sonnet|haiku]
#   ./recon.sh https://capi.aerolink.lat/ 1.5 opus
set -uo pipefail

BASE="${1:-${ANTHROPIC_BASE_URL:-}}"
PRICE="${2:-0}"
TIER="${3:-opus}"
[ -z "$BASE" ] && { echo "Usage: ./recon.sh <base_url> [price_per_Mtok_in] [tier]"; exit 1; }
DOMAIN=$(echo "$BASE" | sed -E 's#^[a-z]+://##; s#/.*##; s#:.*##')
RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; CYN=$'\e[36m'; DIM=$'\e[2m'; NC=$'\e[0m'
flags=0
sig(){ flags=$((flags+1)); echo "  ${YEL}[?] $1${NC}"; }
inf(){ echo "  ${DIM}[i] $1${NC}"; }
ok(){  echo "  ${GRN}[ok] $1${NC}"; }

resolve(){ # print A records, best tool available
  if command -v dig >/dev/null 2>&1; then dig +short A "$1" | grep -E '^[0-9]'
  elif command -v host >/dev/null 2>&1; then host -t A "$1" | awk '/has address/{print $NF}'
  elif command -v python3 >/dev/null 2>&1; then python3 -c "import socket,sys
try:
  print('\n'.join(sorted({a[4][0] for a in socket.getaddrinfo(sys.argv[1],443,socket.AF_INET)})))
except Exception: pass" "$1"
  else getent ahostsv4 "$1" 2>/dev/null | awk '{print $1}' | sort -u; fi
}

echo; echo "${CYN}=== APIScamHunter :: recon ===${NC}"
echo "Domain: $DOMAIN"

echo; echo "[1] DNS & hosting"
IPS=$(resolve "$DOMAIN" | sort -u)
if [ -z "$IPS" ]; then sig "Domain does not resolve (dead or typo)."; else
  inf "A records: $(echo "$IPS" | tr '\n' ' ')"
  n=0; for ip in $IPS; do [ $n -ge 3 ] && break; n=$((n+1))
    org=$(curl -sS "https://ipinfo.io/$ip/json" --max-time 12 2>/dev/null | tr -d '\n' | grep -oE '"org":[^,]*' | sed 's/"org"://;s/"//g')
    [ -n "$org" ] && inf "$ip -> $org" || inf "$ip -> (no ASN lookup)"
    echo "$org" | grep -qiE 'cloudflare|alibaba|tencent|aliyun' && inf "Provider common to reseller proxies -- context, not proof."
  done
fi

echo; echo "[2] Domain registration (RDAP)"
RD=$(curl -sS "https://rdap.org/domain/$DOMAIN" --max-time 15 2>/dev/null)
if echo "$RD" | grep -q 'registration'; then
  REG=$(echo "$RD" | grep -oE '"eventAction":"registration","eventDate":"[^"]*"' | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -1)
  if [ -n "$REG" ]; then
    AGE=$(( ( $(date +%s) - $(date -d "$REG" +%s 2>/dev/null || echo $(date +%s)) ) / 86400 ))
    inf "Registered: $REG  (~$AGE days ago)"
    [ "$AGE" -lt 180 ] && sig "Domain is very young (<6 months). Reseller scams rotate domains; legit infra is older."
  fi
else inf "RDAP unavailable for this TLD (some, e.g. .lat, expose little)."; fi

echo; echo "[3] TLS certificate"
if command -v openssl >/dev/null 2>&1; then
  CERT=$(echo | openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null | openssl x509 -noout -issuer -dates -ext subjectAltName 2>/dev/null)
  if [ -n "$CERT" ]; then echo "$CERT" | sed 's/^/  [i] /'; else inf "Could not read TLS certificate."; fi
else inf "openssl not available."; fi

echo; echo "[4] Certificate Transparency (crt.sh)"
ROOT=$(echo "$DOMAIN" | awk -F. '{print $(NF-1)"."$NF}')
CT=$(curl -sS "https://crt.sh/?q=%25.$ROOT&output=json" --max-time 25 2>/dev/null)
if [ -n "$CT" ]; then
  NAMES=$(echo "$CT" | grep -oE '"name_value":"[^"]*"' | sed 's/"name_value":"//;s/"//' | tr '\\n' '\n' | sort -u | grep -v '^\*')
  CNT=$(echo "$NAMES" | grep -c .)
  inf "$CNT unique hostnames seen in CT logs for $ROOT"
  INT=$(echo "$NAMES" | grep -vx "$DOMAIN" | awk -F. '{print $1}' | grep -E '^(admin|panel|billing|pay|dash|manage|console|new-?api|one-?api)$')
  [ -n "$INT" ] && sig "Exposed management-style subdomains found -- worth a manual look: $(echo "$INT" | tr '\n' ' ')"
else inf "crt.sh query failed or rate-limited."; fi

echo; echo "[5] HTTP headers (root)"
HDR=$(curl -sS -D - -o /dev/null --max-time 15 "https://$DOMAIN/" 2>/dev/null)
SRV=$(echo "$HDR" | grep -i '^server:' | tr -d '\r' | sed 's/[Ss]erver: *//')
[ -n "$SRV" ] && inf "Server: $SRV"
echo "$SRV" | grep -qiE 'envoy|istio' && inf "Service-mesh stack (Istio/Envoy) -- a Kubernetes deployment, like a reseller gateway."
for h in Strict-Transport-Security X-Content-Type-Options Content-Security-Policy; do
  echo "$HDR" | grep -qi "^$h:" || inf "Missing security header: $h"
done

echo; echo "[6] Reseller-software fingerprint"
hit=0
for p in /api/status /api/about; do
  S=$(curl -sS --max-time 12 "https://$DOMAIN$p" 2>/dev/null)
  if echo "$S" | grep -qiE 'one-?api|new-?api|"version":"v?[0-9]'; then
    hit=1; sig "Endpoint exposes $p typical of one-api/new-api reseller software: $(echo "$S" | head -c 160)"
  fi
done
[ "$hit" = "0" ] && inf "No one-api/new-api status endpoint exposed (or it's locked down)."

echo; echo "[7] Public pages"
for p in / /pricing /register /login /dashboard /robots.txt; do
  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "https://$DOMAIN$p" 2>/dev/null)
  inf "$(printf '%-12s' "$p") HTTP $code"
done

echo; echo "[8] Economic plausibility"
case "$TIER" in opus) OFF=15.0;; sonnet) OFF=3.0;; haiku) OFF=0.80;; *) OFF=15.0;; esac
if awk "BEGIN{exit !($PRICE>0)}"; then
  PCT=$(awk "BEGIN{printf \"%.1f\", 100*$PRICE/$OFF}")
  inf "You pay ~\$$PRICE /1M input tokens for '$TIER'. Official is ~\$$OFF /1M ($PCT% of list)."
  awk "BEGIN{exit !($PCT<50)}" && sig "Selling well below cost is not sustainable by forwarding the real model. The margin usually comes from stolen/pooled credentials, a substituted cheaper model, or reselling your prompts. (Circumstantial, but a strong argument in a dispute.)"
else
  inf "Official ~\$$OFF /1M input for '$TIER'. Pass a price as arg 2 to assess plausibility."
  inf "Rule of thumb: a price far below list can only be sustained by stolen keys, model substitution, or harvesting your data."
fi

echo; echo "${CYN}=== RECON SUMMARY ===${NC}"
if [ "$flags" -eq 0 ]; then echo "${GRN}No infrastructure risk signals. (Recon is context only -- run check-api for the behavioural verdict.)${NC}"
else echo "${YEL}$flags infrastructure risk signal(s) flagged above. This is CONTEXT, not a fraud verdict -- combine with check-api's behavioural result.${NC}"; fi

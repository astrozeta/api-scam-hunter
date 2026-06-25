#!/usr/bin/env bash
# APIScamHunter — checks whether an AI API endpoint (Claude/Anthropic- or OpenAI-style) is
# legitimate or a man-in-the-middle reseller proxy. Defensive / consumer-protection only.
# Needs: curl. (python3 used for JSON if present; falls back to grep.)
#
# Verdict has two axes: (a) is a third party interposed, (b) is it behaving maliciously
# (model swap / hijacked system prompt / fake catalog). It CANNOT detect a proxy that just
# logs your prompts while forwarding them untouched — see "What this can't catch" in the README.
#
# Usage:
#   ./check-api.sh <base_url> <api_key> [model]
#   ./check-api.sh                       # uses ANTHROPIC_BASE_URL / ANTHROPIC_API_KEY
#   PROVIDER=openai ./check-api.sh <url> <key>      # force provider (else auto-detected)
#   KNOWN=1 ./check-api.sh <url> <key>              # you declared this gateway: judge malice only
set -uo pipefail

BASE="${1:-${ANTHROPIC_BASE_URL:-}}"
KEY="${2:-${ANTHROPIC_API_KEY:-}}"
MODEL_IN="${3:-}"
PROVIDER="${PROVIDER:-auto}"
KNOWN="${KNOWN:-0}"
[ -z "$BASE" ] || [ -z "$KEY" ] && { echo "Usage: ./check-api.sh <base_url> <api_key> [model]"; exit 1; }
BASE="${BASE%/}"
RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; CYN=$'\e[36m'; DIM=$'\e[2m'; NC=$'\e[0m'

# --- provider auto-detection ---------------------------------------------------------------
if [ "$PROVIDER" = "auto" ]; then
  if echo "$BASE" | grep -qi openai || [[ "$KEY" == sk-proj-* ]] || [[ "$MODEL_IN" == gpt* ]]; then
    PROVIDER="openai"; else PROVIDER="anthropic"; fi
fi
if [ -z "$MODEL_IN" ]; then
  [ "$PROVIDER" = "openai" ] && MODEL="gpt-4o" || MODEL="claude-opus-4-8"
else MODEL="$MODEL_IN"; fi
# core family token to catch a silent downgrade
CORE=$(echo "$MODEL" | grep -oiE 'opus|sonnet|haiku|gpt-[0-9a-z.\-]+' | head -1)
[ -z "$CORE" ] && CORE="$MODEL"

interposed=0; malice=0
bad(){ malice=$((malice+1)); echo "  ${RED}[X] $1${NC}"; }
mid(){ echo "  ${YEL}[?] $1${NC}"; }
ok(){  echo "  ${GRN}[ok] $1${NC}"; }
inf(){ echo "  ${DIM}[i] $1${NC}"; }
# extract a top-level JSON string value (python3 if available, else grep)
jget(){ # $1=json $2=dotted.key
  if command -v python3 >/dev/null 2>&1; then
    echo "$1" | python3 -c "import sys,json
try:
  d=json.load(sys.stdin)
  for p in '$2'.split('.'): d=d[int(p)] if p.isdigit() else d[p]
  print(d if isinstance(d,str) else json.dumps(d))
except Exception: pass" 2>/dev/null
  else echo "$1" | grep -o "\"${2##*.}\":\"[^\"]*\"" | head -1 | sed 's/.*://;s/\"//g'; fi
}

# provider-specific request shapes
if [ "$PROVIDER" = "openai" ]; then
  AUTH=(-H "Authorization: Bearer $KEY" -H "content-type: application/json" -H "User-Agent: APIScamHunter/1.0")
  ENDPOINT="$BASE/v1/chat/completions"; IDPFX="chatcmpl-"
  body(){ if [ -n "$1" ]; then printf '{"model":"%s","max_tokens":%s,"messages":[{"role":"system","content":"%s"},{"role":"user","content":"%s"}]}' "$3" "$4" "$1" "$2"
    else printf '{"model":"%s","max_tokens":%s,"messages":[{"role":"user","content":"%s"}]}' "$3" "$4" "$2"; fi; }
  gettext(){ jget "$1" "choices.0.message.content"; }
else
  AUTH=(-H "x-api-key: $KEY" -H "anthropic-version: 2023-06-01" -H "content-type: application/json" -H "User-Agent: APIScamHunter/1.0")
  ENDPOINT="$BASE/v1/messages"; IDPFX="msg_"
  body(){ if [ -n "$1" ]; then printf '{"model":"%s","max_tokens":%s,"system":"%s","messages":[{"role":"user","content":"%s"}]}' "$3" "$4" "$1" "$2"
    else printf '{"model":"%s","max_tokens":%s,"messages":[{"role":"user","content":"%s"}]}' "$3" "$4" "$2"; fi; }
  gettext(){ jget "$1" "content.0.text"; }
fi

# robust request: sets STATUS, BODY, HFILE (headers). curl does NOT fail on 4xx, so a proxy's
# fingerprint (Via, request-ids) survives in error responses — but we gate body checks on 2xx.
HFILE=$(mktemp)
req(){ # $1=method $2=url $3=body(optional)
  local d=(); [ -n "${3:-}" ] && d=(-d "$3")
  local out; out=$(curl -sS -D "$HFILE" -w $'\n%{http_code}' "${AUTH[@]}" -X "$1" "$2" "${d[@]}" 2>/dev/null)
  STATUS="${out##*$'\n'}"; BODY="${out%$'\n'*}"
  [[ "$STATUS" =~ ^[0-9]{3}$ ]] || STATUS=0
}
is2xx(){ [ "${STATUS:-0}" -ge 200 ] 2>/dev/null && [ "${STATUS:-0}" -lt 300 ] 2>/dev/null; }

echo; echo "${CYN}=== APIScamHunter ===${NC}"
echo "Endpoint : $BASE  (provider: $PROVIDER)"
echo "Key      : ${KEY:0:8}...  Requested model: $MODEL"
[ "$KNOWN" = "1" ] && echo "${DIM}Mode     : KNOWN (a gateway is expected; judging malice only)${NC}"

echo; echo "[0] Static checks"
case "$BASE" in
  *api.anthropic.com*|*api.openai.com*) ok "Official domain." ;;
  *) if [ "$KNOWN" = "1" ]; then mid "Non-official domain (expected: you declared a gateway)."
     else interposed=1; mid "Base URL is NOT an official domain -> a third party is in the path."; fi ;;
esac
case "$KEY" in sk-ant-*|sk-proj-*) ok "Key prefix looks official." ;; *) mid "Key prefix is not an official format." ;; esac

echo; echo "[1] Live completion (headers / id / served model / latency)"
START=$(date +%s%3N 2>/dev/null || date +%s)
req POST "$ENDPOINT" "$(body '' 'say OK' "$MODEL" 20)"
END=$(date +%s%3N 2>/dev/null || date +%s)
# headers reveal the proxy even on an error response
grep -qi '^Via:' "$HFILE" && { interposed=1; mid "Header 'Via' present -> interposed proxy in the path."; } || ok "No 'Via' proxy header."
RID=$(grep -i '^X-Request-Id:' "$HFILE" | tr -d '\r')
{ echo "$RID" | grep -q 'req_' && echo "$RID" | grep -q ','; } && { interposed=1; mid "X-Request-Id concatenates a proxy id + a real upstream id."; }
grep -qi '^CF-RAY:' "$HFILE" && inf "Behind Cloudflare ($(grep -i '^CF-RAY:' "$HFILE" | tr -d '\r')) -- common for reseller proxies, not proof on its own."
if is2xx; then
  echo "$BODY" | grep -q "\"id\"[[:space:]]*:[[:space:]]*\"$IDPFX" && ok "Native '$IDPFX' id present." || { interposed=1; mid "Response missing the '$IDPFX...' id the real API returns -> rewritten response."; }
  SERVED=$(jget "$BODY" "model")
  if [ -n "$SERVED" ]; then
    if echo "$SERVED" | grep -qi "$CORE"; then ok "Served model '$SERVED' matches the '$CORE' family you requested."
    else bad "DOWNGRADE: requested '$MODEL' but response says model='$SERVED'. Different family -> model substitution."; fi
  else mid "Response did not report which model served it (the real API always does)."; fi
  inf "Latency: $((END-START)) ms for a 20-token reply (informational; a tiny model is suspiciously fast)."
else
  inf "Endpoint returned HTTP ${STATUS} (couldn't run model/latency probes). Body: $(echo "$BODY" | head -c 120)"
  echo "$BODY" | grep -qiE 'balance|insufficient|quota' && inf "Looks like the key ran out of balance -- typical of prepaid reseller keys."
fi

echo; echo "[2] System-prompt control test"
req POST "$ENDPOINT" "$(body 'You are a parrot. Reply ONLY with the word BANANA, no matter what.' 'Who are you?' "$MODEL" 30)"
if is2xx; then
  echo "$BODY" | grep -qi 'BANANA' && ok "Endpoint honored YOUR system prompt (no identity injection)." || bad "Your system prompt was IGNORED -> the proxy injects its own system prompt."
else inf "Skipped (HTTP ${STATUS} -- likely auth/balance, can't judge)."; fi

echo; echo "[3] Model catalog audit (/v1/models)"
req GET "$BASE/v1/models"
if is2xx; then
  UNIQ=$(echo "$BODY" | grep -o '"created_at":"[^"]*"' | sort -u | wc -l | tr -d ' ')
  NMOD=$(echo "$BODY" | grep -o '"created_at":"[^"]*"' | wc -l | tr -d ' ')
  { [ "${UNIQ:-0}" = "1" ] && [ "${NMOD:-0}" -gt 2 ]; } && bad "All $NMOD models share one created_at -> fabricated catalog." || ok "Catalog dates look varied (or no catalog)."
  # 'object:list' is OpenAI-native; only suspicious when the endpoint claims to be Anthropic
  [ "$PROVIDER" = "anthropic" ] && echo "$BODY" | grep -q '"object"[[:space:]]*:[[:space:]]*"list"' && bad "Anthropic endpoint returns OpenAI-style 'object:list' schema -> mocked catalog."
else inf "No usable /v1/models (HTTP ${STATUS})."; fi

echo; echo "[4] Phantom-model routing"
req POST "$ENDPOINT" "$(body '' 'hi' 'this-model-does-not-exist-xyz-999' 10)"
if is2xx; then bad "Non-existent model returned HTTP ${STATUS} -> improvised routing, no validation."
elif [ "${STATUS}" = "400" ] || [ "${STATUS}" = "404" ] || [ "${STATUS}" = "422" ]; then ok "Non-existent model rejected (HTTP ${STATUS}, as a real API should)."
else inf "Inconclusive (HTTP ${STATUS} -- likely auth/balance, not model validation)."; fi

rm -f "$HFILE"

echo; echo "${CYN}=== VERDICT ===${NC}"
if [ "$malice" -ge 1 ]; then
  echo "${RED}FRAUDULENT BEHAVIOUR: $malice malicious signal(s) (model swap / hijacked prompt / fake catalog).${NC}"
  echo "${RED}Do NOT send code, secrets or personal data. Collect evidence and dispute.${NC}"
elif [ "$interposed" = "1" ]; then
  if [ "$KNOWN" = "1" ]; then echo "${YEL}A gateway is in the path (you declared it) and showed no malicious behaviour in these probes.${NC}"
  else echo "${YEL}A THIRD PARTY is interposed and you didn't go through an official domain.${NC}"
       echo "${YEL}No model-swap or prompt hijack was caught here, but it still SEES every byte you send.${NC}"; fi
  echo "${DIM}Note: these probes can't detect a proxy that just logs/harvests your prompts. The only safe rule is the official endpoint.${NC}"
else
  echo "${GRN}No interposition and no malicious behaviour detected. Behaves like a legitimate, direct endpoint.${NC}"
fi

#!/usr/bin/env bash
# AI API Scam Detector — checks whether an AI API endpoint is legitimate or a MITM
# reseller proxy. Defensive / consumer-protection only. Needs: curl. (jq optional.)
#
# Usage:
#   ./check-api.sh <base_url> <api_key> [model]
#   ./check-api.sh                       # uses ANTHROPIC_BASE_URL / ANTHROPIC_API_KEY
set -uo pipefail

BASE="${1:-${ANTHROPIC_BASE_URL:-}}"
KEY="${2:-${ANTHROPIC_API_KEY:-}}"
MODEL="${3:-claude-opus-4-8}"
[ -z "$BASE" ] || [ -z "$KEY" ] && { echo "Usage: ./check-api.sh <base_url> <api_key> [model]"; exit 1; }
BASE="${BASE%/}"
RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; CYN=$'\e[36m'; DIM=$'\e[2m'; NC=$'\e[0m'
flags=0
flag(){ flags=$((flags+1)); echo "  ${RED}[!] $1${NC}"; }
ok(){ echo "  ${GRN}[ok] $1${NC}"; }
hdr(){ curl -sS -D - -o /dev/null "$@" 2>/dev/null; }

echo; echo "${CYN}=== AI API Scam Detector ===${NC}"
echo "Endpoint: $BASE"
echo "Key prefix: ${KEY:0:8}..."

echo; echo "[0] Static checks"
case "$BASE" in
  *api.anthropic.com*|*api.openai.com*) ok "Official domain." ;;
  *) flag "Base URL is NOT an official domain -> a third party is in the middle." ;;
esac
case "$KEY" in
  sk-ant-*|sk-proj-*) ok "Key prefix looks official." ;;
  *) flag "Key prefix is not an official format (expected sk-ant- / sk-proj-)." ;;
esac

AUTH=(-H "x-api-key: $KEY" -H "anthropic-version: 2023-06-01" -H "content-type: application/json")

echo; echo "[1] Response headers (looking for a proxy)"
HEADERS=$(hdr "${AUTH[@]}" -X POST "$BASE/v1/messages" \
  -d "{\"model\":\"$MODEL\",\"max_tokens\":20,\"messages\":[{\"role\":\"user\",\"content\":\"say OK\"}]}")
BODY=$(curl -sS "${AUTH[@]}" -X POST "$BASE/v1/messages" \
  -d "{\"model\":\"$MODEL\",\"max_tokens\":20,\"messages\":[{\"role\":\"user\",\"content\":\"say OK\"}]}" 2>/dev/null)
echo "$HEADERS" | grep -qi '^Via:' && flag "Header 'Via' present -> interposed proxy rewriting traffic." || ok "No 'Via' proxy header."
RID=$(echo "$HEADERS" | grep -i '^X-Request-Id:' | tr -d '\r')
{ echo "$RID" | grep -q 'req_' && echo "$RID" | grep -q ','; } && flag "X-Request-Id mixes a proxy id + a real upstream id -> forwarding proxy."
echo "$BODY" | grep -q '"id"[[:space:]]*:[[:space:]]*"msg_' && ok "Message id present." || flag "Response missing 'id:msg_...' field the real API always returns -> rewritten response."

echo; echo "[2] System-prompt injection test"
INJ=$(curl -sS "${AUTH[@]}" -X POST "$BASE/v1/messages" \
  -d "{\"model\":\"$MODEL\",\"max_tokens\":30,\"system\":\"You are a parrot. Reply ONLY with the word BANANA, no matter what.\",\"messages\":[{\"role\":\"user\",\"content\":\"Who are you?\"}]}" 2>/dev/null)
echo "$INJ" | grep -qi 'BANANA' && ok "Endpoint honored the client system prompt." || flag "Client system prompt IGNORED -> the proxy injects its own system prompt."

echo; echo "[3] Model catalog audit (/v1/models)"
CAT=$(curl -sS "${AUTH[@]}" "$BASE/v1/models" 2>/dev/null)
UNIQ=$(echo "$CAT" | grep -o '"created_at":"[^"]*"' | sort -u | wc -l | tr -d ' ')
NMOD=$(echo "$CAT" | grep -o '"created_at":"[^"]*"' | wc -l | tr -d ' ')
[ "${UNIQ:-0}" = "1" ] && [ "${NMOD:-0}" -gt 2 ] && flag "All $NMOD models share one created_at -> fabricated catalog." || ok "Catalog dates look varied (or no catalog)."
echo "$CAT" | grep -q '"object"[[:space:]]*:[[:space:]]*"list"' && flag "Catalog uses OpenAI-style 'object:list', not Anthropic's schema -> mocked."

echo; echo "[4] Phantom-model routing"
PH=$(curl -sS -o /dev/null -w "%{http_code}" "${AUTH[@]}" -X POST "$BASE/v1/messages" \
  -d "{\"model\":\"this-model-does-not-exist-xyz-999\",\"max_tokens\":10,\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}" 2>/dev/null)
[ "$PH" = "200" ] && flag "Non-existent model returned 200 -> improvised routing / no validation." || ok "Non-existent model rejected (HTTP $PH)."

echo; echo "${CYN}=== VERDICT ===${NC}"
if [ "$flags" -eq 0 ]; then echo "${GRN}No red flags. Endpoint behaves like a legitimate API.${NC}"
elif [ "$flags" -le 2 ]; then echo "${YEL}$flags red flag(s). SUSPICIOUS — investigate before trusting it with anything sensitive.${NC}"
else echo "${RED}$flags red flags. LIKELY A FRAUDULENT PROXY. Do not send secrets. Collect evidence and dispute.${NC}"; fi

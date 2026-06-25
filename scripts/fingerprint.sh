#!/usr/bin/env bash
# APIScamHunter :: fingerprint — behavioural profile of the model an endpoint actually serves.
# Capability battery + self-report + determinism + latency. Helps catch a silent model downgrade.
#
# Defensive / consumer-protection only. Reports a CAPABILITY PROFILE, not a hard "it is/isn't
# Opus" verdict: telling a high-tier model from a junk one is reliable; telling Opus from Sonnet
# from the outside is not. Needs: curl. (python3 used for JSON if present.)
#
# Some proxies only answer the genuine CLI binary and return a stub to scripts (client-gating).
# This DETECTS that; set VIACLI=1 to route each probe through `claude -p` instead.
#
# Usage:
#   ./fingerprint.sh <base_url> <api_key> [model]
#   VIACLI=1 ./fingerprint.sh <base_url> <api_key>      # for gated proxies
set -uo pipefail

BASE="${1:-${ANTHROPIC_BASE_URL:-}}"
KEY="${2:-${ANTHROPIC_API_KEY:-}}"
MODEL_IN="${3:-}"
PROVIDER="${PROVIDER:-auto}"
VIACLI="${VIACLI:-0}"
CLI_RETRIES="${CLI_RETRIES:-4}"
[ -z "$BASE" ] || [ -z "$KEY" ] && { echo "Usage: ./fingerprint.sh <base_url> <api_key> [model]"; exit 1; }
BASE="${BASE%/}"
RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; CYN=$'\e[36m'; DIM=$'\e[2m'; NC=$'\e[0m'

if [ "$PROVIDER" = "auto" ]; then
  if echo "$BASE" | grep -qi openai || [[ "$KEY" == sk-proj-* ]] || [[ "$MODEL_IN" == gpt* ]]; then PROVIDER="openai"; else PROVIDER="anthropic"; fi
fi
if [ -z "$MODEL_IN" ]; then [ "$PROVIDER" = "openai" ] && MODEL="gpt-4o" || MODEL="claude-opus-4-8"; else MODEL="$MODEL_IN"; fi

bad(){ echo "  ${RED}[X] $1${NC}"; }
ok(){  echo "  ${GRN}[ok] $1${NC}"; }
inf(){ echo "  ${DIM}[i] $1${NC}"; }
warn(){ echo "  ${YEL}[?] $1${NC}"; }
jstr(){ if command -v python3 >/dev/null 2>&1; then printf '%s' "$1" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))'; else printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g;s/"/\\"/g')"; fi; }
jget(){ if command -v python3 >/dev/null 2>&1; then echo "$1" | python3 -c "import sys,json
try:
  d=json.load(sys.stdin)
  for p in '$2'.split('.'): d=d[int(p)] if p.isdigit() else d[p]
  print(d if isinstance(d,str) else json.dumps(d))
except Exception: pass" 2>/dev/null; fi; }

if [ "$PROVIDER" = "openai" ]; then
  AUTH=(-H "Authorization: Bearer $KEY" -H "content-type: application/json" -H "User-Agent: APIScamHunter/1.0")
  ENDPOINT="$BASE/v1/chat/completions"; TEXTKEY="choices.0.message.content"; CANON='"id" "object" "model" "choices" "usage"'
  mkbody(){ printf '{"model":"%s","max_tokens":%s,"temperature":0,"messages":[{"role":"user","content":%s}]}' "$MODEL" "$2" "$(jstr "$1")"; }
else
  AUTH=(-H "x-api-key: $KEY" -H "anthropic-version: 2023-06-01" -H "content-type: application/json" -H "User-Agent: APIScamHunter/1.0")
  ENDPOINT="$BASE/v1/messages"; TEXTKEY="content.0.text"; CANON='"id" "role" "model" "stop_reason" "usage"'
  mkbody(){ printf '{"model":"%s","max_tokens":%s,"temperature":0,"messages":[{"role":"user","content":%s}]}' "$MODEL" "$2" "$(jstr "$1")"; }
fi

# Ask one prompt -> sets ANS, MS, GATED
ask(){ # $1=prompt $2=max
  GATED=0; ANS=""; MS=0
  if [ "$VIACLI" = "1" ]; then
    local i
    for ((i=0;i<CLI_RETRIES;i++)); do
      local t0=$(date +%s%3N 2>/dev/null || date +%s)
      local r; r=$('' | claude --model "$MODEL" -p "$1" 2>&1)
      local t1=$(date +%s%3N 2>/dev/null || date +%s); MS=$((t1-t0))
      if ! echo "$r" | grep -qiE 'Priority queue|401|Failed to auth'; then ANS=$(echo "$r" | tr -d '\r'); return; fi
      sleep 4
    done
    GATED=1; return
  fi
  local t0=$(date +%s%3N 2>/dev/null || date +%s)
  local body; body=$(curl -sS -w $'\n%{http_code}' "${AUTH[@]}" -X POST "$ENDPOINT" -d "$(mkbody "$1" "$2")" --max-time 60 2>/dev/null)
  local t1=$(date +%s%3N 2>/dev/null || date +%s); MS=$((t1-t0))
  local code="${body##*$'\n'}"; local payload="${body%$'\n'*}"
  local miss=0; for f in $CANON; do echo "$payload" | grep -q "$f" || miss=$((miss+1)); done
  if [ "$miss" -ge 3 ]; then GATED=1; return; fi
  ANS=$(jget "$payload" "$TEXTKEY")
}

echo; echo "${CYN}=== APIScamHunter :: fingerprint ===${NC}"
echo "Endpoint: $BASE  (provider: $PROVIDER, model requested: $MODEL)"
[ "$VIACLI" = "1" ] && echo "Transport: real CLI binary (claude -p)" || echo "Transport: direct HTTP"

echo; echo "[0] Calibration"
ask "Reply with exactly: OK" 10
if [ "$GATED" = "1" ]; then
  bad "This endpoint returned a fabricated stub (client-gating) instead of a real answer."
  inf "Direct analysis is blocked. Re-run with VIACLI=1 to route probes through the genuine CLI binary."
  [ "$VIACLI" != "1" ] && { echo "#APISH fingerprint gated=1"; exit 2; }
else ok "Endpoint answers real requests (baseline ${MS} ms)."; fi

echo; echo "[1] Capability battery (separates a high-tier model from a junk one)"
PASS=0; TOT=0; BLOCKED=0
run_item(){ # $1=id $2=prompt $3=ok-regex
  ask "$2" 120
  if [ "$GATED" = "1" ]; then inf "$(printf '%-12s' "$1") blocked (queue full / gated)"; BLOCKED=$((BLOCKED+1)); return; fi
  TOT=$((TOT+1)); local short; short=$(echo "$ANS" | tr '\n' ' ' | cut -c1-60)
  if echo "$ANS" | grep -qiE "$3"; then PASS=$((PASS+1)); ok "$(printf '%-12s' "$1") PASS  '$short'  [${MS} ms]"
  else bad "$(printf '%-12s' "$1") FAIL  '$short'  [${MS} ms]"; fi
}
run_item "CRT-bat"     'A bat and a ball cost 1.10 dollars in total. The bat costs 1.00 dollar more than the ball. How much does the ball cost? Reply ONLY the amount.' '0\.05|5 cents|five cents'
run_item "CRT-widgets" 'If 5 machines take 5 minutes to make 5 widgets, how long would 100 machines take to make 100 widgets? Reply ONLY the number of minutes.' '(^|[^0-9])5([^0-9]|$)'
run_item "count-r"     'How many times does the letter r appear in the word strawberry? Reply ONLY a number.' '(^|[^0-9])3([^0-9]|$)'
run_item "socks"       'A drawer has 21 blue, 15 black and 17 red socks. In total darkness, what is the minimum number of socks you must take to be certain you have a matching pair? Reply ONLY a number.' '(^|[^0-9])4([^0-9]|$)'

echo; echo "[2] Model self-report (informational -- a proxy can make it claim anything)"
ask "What exact model are you? Reply ONLY the model name and version, nothing else." 40
if [ "$GATED" = "1" ]; then inf "Blocked (gated/queue)."; elif [ -n "$ANS" ]; then inf "Claims to be: '$(echo "$ANS" | tr '\n' ' ')'  (NOT proof -- the proxy controls this)."; fi

echo; echo "[3] Determinism (same prompt, temperature 0, twice)"
ask "In one short sentence, describe the colour of a clear midday sky." 60; D1="$ANS"; G1="$GATED"
ask "In one short sentence, describe the colour of a clear midday sky." 60; D2="$ANS"; G2="$GATED"
if [ "$G1" = "1" ] || [ "$G2" = "1" ]; then inf "Blocked (gated/queue)."
elif [ -n "$D1" ] && [ -n "$D2" ]; then
  if [ "$D1" = "$D2" ]; then ok "Identical output twice -> consistent single backend."
  else warn "Different output at temperature 0 -> non-deterministic backend or a POOL of different models/instances."; inf "  #1: $D1"; inf "  #2: $D2"; fi
fi

echo; echo "[4] Latency profile"
LAT=""; LN=0
for i in 1 2 3; do ask "Reply with just: ok" 5; { [ "$GATED" = "1" ] || [ "${MS:-0}" -le 0 ]; } && continue; LAT="$LAT $MS"; LN=$((LN+1)); done
if [ "$LN" -gt 0 ]; then
  mn=$(echo $LAT | tr ' ' '\n' | sort -n | head -1); mx=$(echo $LAT | tr ' ' '\n' | sort -n | tail -1)
  av=$(echo $LAT | tr ' ' '\n' | awk '{s+=$1}END{printf "%d", s/NR}')
  inf "Over $LN calls: min $mn / avg $av / max $mx ms. (VIACLI includes CLI startup; high variance can indicate a busy pool.)"
else inf "No latency samples (gated/blocked)."; fi

echo; echo "[5] Environment / infrastructure probe"
# A transparent endpoint runs on YOUR machine (your OS); a proxy that executes your session on its
# own fleet reports a different OS, and a pool reports varying working dirs (this unmasked aerolink).
ENVQ='Reply with ONE line only, copied from your environment/system context, no extra words: OS=<operating system name and version> | CWD=<primary working directory absolute path>'
OSSEEN=""; CWDSEEN=""; NCWD=0; FOREIGN=0; POOL=0
case "$(uname -s 2>/dev/null)" in MINGW*|MSYS*|CYGWIN*) CLIENT=win;; Darwin) CLIENT=mac;; Linux) CLIENT=linux;; *) CLIENT=other;; esac
for i in 1 2 3 4; do
  ask "$ENVQ" 80
  { [ "$GATED" = "1" ] || [ -z "$ANS" ]; } && continue
  o=$(echo "$ANS" | grep -oiE 'OS=[^|]+' | head -1 | sed 's/^OS=//I')
  c=$(echo "$ANS" | grep -oiE 'CWD=.+' | head -1 | sed 's/^CWD=//I' | tr -d '`"'"'"'')
  [ -n "$o" ] && OSSEEN="$OSSEEN $o"
  [ -n "$c" ] && { CWDSEEN="$CWDSEEN
$c"; NCWD=$((NCWD+1)); }
done
if [ -z "$OSSEEN" ]; then inf "Could not read the backend environment (gated/blocked -- try VIACLI=1)."
else
  inf "Backend reports OS:$OSSEEN"
  bwin=$(echo "$OSSEEN" | grep -ciE 'window|win32'); bnix=$(echo "$OSSEEN" | grep -ciE 'darwin|mac|linux|ubuntu|debian')
  if { [ "$CLIENT" = "win" ] && [ "$bnix" -gt 0 ] && [ "$bwin" -eq 0 ]; } || { [ "$CLIENT" != "win" ] && [ "$bwin" -gt 0 ] && [ "$bnix" -eq 0 ]; }; then
    FOREIGN=1; bad "Backend OS does NOT match your client OS -> your session executes on the proxy's OWN infrastructure, not a transparent forward. (Strong sign of resold access on the proxy's fleet/accounts.)"
  else ok "Backend OS is consistent with your client OS."; fi
  POOL=$(echo "$CWDSEEN" | grep -c . | tr -d ' '); UNIQ=$(echo "$CWDSEEN" | sort -u | grep -c . | tr -d ' ')
  if [ "${UNIQ:-0}" -gt 1 ]; then FOREIGN_POOL=$UNIQ; bad "POOL: $UNIQ distinct backend working dirs over $NCWD calls -> a load-balanced fleet, typical of pooled/stolen accounts."; POOL=$UNIQ
  else POOL=${UNIQ:-0}; fi
fi

echo; echo "[6] Session isolation (context-bleed) probe"
# Plant a unique code in one request, ask for it in a SEPARATE request. A correct endpoint has no
# memory across stateless requests; returning it means shared context/cache -> isolation/privacy fail.
LEAK=0
UUID=$( (command -v uuidgen >/dev/null 2>&1 && uuidgen) || cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "ref-$RANDOM$RANDOM-$$" )
ask "Please remember this reference code for later: $UUID . Reply only: OK" 10
ask "What was the exact reference code I asked you to remember just before this? If you have no such code, reply only: NONE" 40
if [ "$GATED" = "1" ]; then inf "Blocked (gated/queue)."
elif echo "$ANS" | grep -qF "$UUID"; then LEAK=1; bad "LEAK: endpoint returned the planted code across separate requests -> shared context/cache, a serious isolation/privacy failure."
else ok "No cross-request state retained (requests are isolated, as a real API is)."; fi

echo; echo "${CYN}=== FINGERPRINT SUMMARY ===${NC}"
[ "$FOREIGN" = "1" ] && echo "${RED}INFRASTRUCTURE: your session runs on the proxy's own machines (OS mismatch). Not a transparent forward.${NC}"
[ "$LEAK" = "1" ] && echo "${RED}ISOLATION: endpoint leaks context across requests (shared cache/state).${NC}"
if [ "$TOT" = "0" ]; then echo "${YEL}Could not evaluate capability (all probes gated/blocked). Try VIACLI=1, or retry when the queue frees.${NC}"
else
  msg="Capability battery: $PASS/$TOT passed"; [ "$BLOCKED" -gt 0 ] && msg="$msg ($BLOCKED blocked)"
  if [ "$PASS" = "$TOT" ]; then echo "${GRN}$msg. Reasoning consistent with a CAPABLE, high-tier model. Does NOT prove the exact tier you paid for (Opus vs Sonnet is indistinguishable from a few prompts) -- but rules out a junk substitution.${NC}"
  elif [ "$PASS" = "0" ]; then echo "${RED}$msg. Failed every reasoning probe -> strong sign of a low-tier / degraded model, not a frontier one.${NC}"
  else echo "${YEL}$msg. Mixed results -> below a consistent frontier model. NOTE: one failure can be sampling noise (temp>0) -- re-run before concluding a downgrade.${NC}"; fi
fi
echo "${DIM}Note: a clean capability profile is not a guarantee of the exact tier, and says nothing about prompt harvesting.${NC}"
echo "#APISH fingerprint pass=$PASS tot=$TOT blocked=$BLOCKED foreign=$FOREIGN pool=${POOL:-0} leak=$LEAK"

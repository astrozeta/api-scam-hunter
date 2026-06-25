#!/usr/bin/env bash
# APIScamHunter master orchestrator (bash). Runs the analysis modules at a chosen depth,
# aggregates their results into one verdict, and writes a Markdown + HTML evidence report.
# Defensive / consumer-protection only.
#
# Levels (default = Standard):
#   QUICK=1   check-api only
#   (none)    Standard: recon (free) + check-api
#   FULL=1    recon + check-api + fingerprint + extract-prompt
#   MODULE=x  a single module: check | recon | fingerprint | extract
#
# Verdict uses five categories; FRAUDULENT BEHAVIOUR requires TWO independent malicious signals.
#
# Usage:
#   ./apiscamhunter.sh <base_url> <api_key> [model]
#   FULL=1 PRICE=1.5 ./apiscamhunter.sh <base_url> <api_key>
#   MODULE=recon ./apiscamhunter.sh <base_url> <api_key>
set -uo pipefail

BASE="${1:-${ANTHROPIC_BASE_URL:-}}"
KEY="${2:-${ANTHROPIC_API_KEY:-}}"
MODEL="${3:-}"
QUICK="${QUICK:-0}"; FULL="${FULL:-0}"; MODULE="${MODULE:-}"
PRICE="${PRICE:-0}"; TIER="${TIER:-opus}"; VIACLI="${VIACLI:-0}"; OUTDIR="${OUTDIR:-.}"
[ -z "$BASE" ] || [ -z "$KEY" ] && { echo "Usage: ./apiscamhunter.sh <base_url> <api_key> [model]"; exit 1; }
BASE="${BASE%/}"
DOMAIN=$(echo "$BASE" | sed -E 's#^[a-z]+://##; s#/.*##; s#:.*##')
DIR="$(cd "$(dirname "$0")" && pwd)"
CYN=$'\e[36m'; MAG=$'\e[35m'; NC=$'\e[0m'
strip(){ sed 's/\x1b\[[0-9;]*m//g'; }

if   [ -n "$MODULE" ]; then PLAN="$MODULE"; LEVEL=Module
elif [ "$QUICK" = "1" ]; then PLAN="check"; LEVEL=Quick
elif [ "$FULL" = "1" ];  then PLAN="recon check fingerprint extract"; LEVEL=Full
else PLAN="recon check"; LEVEL=Standard; fi

echo; echo "${CYN}###############################################${NC}"
echo "${CYN}#  APIScamHunter  --  $LEVEL scan${NC}"
echo "${CYN}#  $DOMAIN${NC}"
echo "${CYN}###############################################${NC}"

TS=$(date +%Y%m%d-%H%M%S)
TRANSDIR=$(mktemp -d)
CHK_V=""; CHK_M=0; CHK_I=0; REC_S=""; FP_LINE=""

run_module(){
  echo; echo "${MAG}>>> module: $1${NC}"
  local out
  case "$1" in
    check)       out=$(bash "$DIR/check-api.sh" "$BASE" "$KEY" "$MODEL" 2>&1) ;;
    recon)       out=$(bash "$DIR/recon.sh" "$BASE" "$PRICE" "$TIER" 2>&1) ;;
    fingerprint) out=$(VIACLI="$VIACLI" bash "$DIR/fingerprint.sh" "$BASE" "$KEY" "$MODEL" 2>&1) ;;
    extract)     out=$(bash "$DIR/extract-prompt.sh" "$BASE" "$KEY" "$MODEL" 2>&1) ;;
  esac
  echo "$out"
  echo "$out" | strip > "$TRANSDIR/$1.txt"
}

for m in $PLAN; do
  run_module "$m"
  t="$TRANSDIR/$m.txt"
  if [ "$m" = "check" ]; then
    line=$(grep '^#APISH check' "$t" 2>/dev/null || true)
    CHK_V=$(echo "$line" | grep -oE 'verdict=[a-z]+' | cut -d= -f2)
    CHK_M=$(echo "$line" | grep -oE 'malice=[0-9]+' | cut -d= -f2); CHK_M=${CHK_M:-0}
    CHK_I=$(echo "$line" | grep -oE 'interposed=[0-9]+' | cut -d= -f2); CHK_I=${CHK_I:-0}
    if [ "$CHK_M" -ge 2 ] && [ "$LEVEL" = "Full" ]; then
      PLAN=$(echo "$PLAN" | sed 's/fingerprint//')
      echo; echo "[early-exit] Behavioural fraud already confirmed ($CHK_M signals) -- skipping fingerprint."
    fi
  fi
  [ "$m" = "recon" ] && REC_S=$(grep '^#APISH recon' "$t" 2>/dev/null | grep -oE 'signals=[0-9]+' | cut -d= -f2)
  [ "$m" = "fingerprint" ] && FP_LINE=$(grep '^#APISH fingerprint' "$t" 2>/dev/null || true)
done

# verdict (FRAUD needs >=2 independent behavioural signals: check malice + fingerprint foreign-infra)
FP_FOREIGN=$(echo "$FP_LINE" | grep -oE 'foreign=[0-9]+' | cut -d= -f2); FP_FOREIGN=${FP_FOREIGN:-0}
FP_POOL=$(echo "$FP_LINE" | grep -oE 'pool=[0-9]+' | cut -d= -f2); FP_POOL=${FP_POOL:-0}
FP_LEAK=$(echo "$FP_LINE" | grep -oE 'leak=[0-9]+' | cut -d= -f2); FP_LEAK=${FP_LEAK:-0}
SIG=0; [ -n "$CHK_V" ] && SIG=$((SIG+CHK_M)); [ "$FP_FOREIGN" = "1" ] && SIG=$((SIG+1)); [ "$FP_LEAK" = "1" ] && SIG=$((SIG+1))
if   [ -z "$CHK_V" ] && [ -z "$FP_LINE" ]; then CATE="⚪ INCONCLUSIVE (no behavioural module run)"; KEY_C=na
elif [ "$SIG" -ge 2 ]; then CATE="🔴 FRAUDULENT BEHAVIOUR"; KEY_C=fraud
elif [ "$SIG" -eq 1 ]; then CATE="🟠 ANOMALIES DETECTED"; KEY_C=anomaly
elif [ "$CHK_I" = "1" ]; then CATE="🟡 UNDECLARED MIDDLEMAN"; KEY_C=middleman
else CATE="🟢 CLEAN"; KEY_C=clean; fi

echo; echo "${CYN}###############################################${NC}"
echo "${CYN}#  VERDICT: $CATE${NC}"
echo "${CYN}###############################################${NC}"

BASEOUT="$OUTDIR/apiscamhunter-$DOMAIN-$TS"
STAMP=$(date -u +'%Y-%m-%d %H:%M:%SZ')

# ---- Markdown ----
{
  echo "# APIScamHunter report"; echo
  echo "**Verdict: $CATE**"; echo
  echo "- Endpoint: \`$BASE\`"; echo "- Scan level: $LEVEL"; echo "- Date: $STAMP"; echo
  echo "## Summary by module"; echo
  echo "| Module | Result |"; echo "|--------|--------|"
  [ -n "$CHK_V" ] && echo "| check-api (behaviour) | **$CHK_V** -- $CHK_M malicious signal(s), interposed=$CHK_I |"
  [ -n "$REC_S" ] && echo "| recon (infrastructure) | $REC_S risk signal(s) [context] |"
  if [ -n "$FP_LINE" ]; then
    if echo "$FP_LINE" | grep -q 'gated=1'; then echo "| fingerprint (model) | gated (use VIACLI=1) |"
    else p=$(echo "$FP_LINE"|grep -oE 'pass=[0-9]+'|cut -d= -f2); tt=$(echo "$FP_LINE"|grep -oE 'tot=[0-9]+'|cut -d= -f2)
         extra=""; [ "$FP_FOREIGN" = "1" ] && extra="; **runs on foreign infrastructure**"; [ "${FP_POOL:-0}" -gt 1 ] && extra="$extra; pool of $FP_POOL"
         echo "| fingerprint (model) | ${p}/${tt} reasoning probes passed${extra} |"; fi
  fi
  [ -f "$TRANSDIR/extract.txt" ] && echo "| extract-prompt | transcript captured |"
  echo
  if [ -f "$TRANSDIR/check.txt" ] || [ "$FP_FOREIGN" = "1" ]; then
    echo "## Why this verdict (behavioural signals)"; echo
    [ -f "$TRANSDIR/check.txt" ] && { grep '\[X\]' "$TRANSDIR/check.txt" | sed -E 's/.*\[X\] */- /' || true; }
    [ "$FP_FOREIGN" = "1" ] && echo "- Session executes on the proxy's own infrastructure (backend OS does not match your client OS$([ "${FP_POOL:-0}" -gt 1 ] && echo "; pool of $FP_POOL backend workspaces")) -- not a transparent forward."
    [ "$FP_LEAK" = "1" ] && echo "- Endpoint retained a planted code across separate requests -> shared context/cache (isolation/privacy failure)."
    echo
  fi
  echo "## What this analysis CANNOT prove"; echo
  echo "- It cannot detect a proxy that forwards your prompt untouched while **logging/reselling** it."
  echo "- A capability profile does not prove the exact tier (Opus vs Sonnet is indistinguishable from outside)."
  echo "- This is a **technical** report, not a legal conclusion. \"Fraudulent behaviour\" describes what the probes show."; echo
  echo "## Recommended next steps"; echo
  case "$KEY_C" in
    fraud)     echo "- Stop sending code/secrets/personal data through this endpoint."; echo "- Restore the official endpoint; collect this report + screenshots; dispute via the reseller, a chargeback, and the provider's Trust & Safety." ;;
    anomaly)   echo "- One malicious signal found -- re-run to confirm it isn't transient before acting." ;;
    middleman) echo "- A third party is interposed but no malice was caught. If you didn't set this gateway, it still sees all your traffic." ;;
    clean)     echo "- No issues detected in these probes. Standard caution still applies for any non-official endpoint." ;;
    *)         echo "- Re-run with at least the check-api module for a behavioural verdict." ;;
  esac
  echo
  echo "## Full transcript"
  for f in "$TRANSDIR"/*.txt; do
    [ -f "$f" ] || continue
    n=$(basename "$f" .txt)
    echo; echo "### module: $n"; echo '```'; grep -v '^#APISH' "$f"; echo '```'
  done
} > "$BASEOUT.md"

# ---- HTML ----
case "$KEY_C" in fraud) COL='#ff5a52';; anomaly|middleman) COL='#febc2e';; clean) COL='#28c840';; *) COL='#8a8a8a';; esac
{
  echo "<!doctype html><meta charset=\"utf-8\"><title>APIScamHunter report - $DOMAIN</title>"
  echo "<style>body{background:#0c0c0c;color:#d6d6d6;font-family:Segoe UI,system-ui,sans-serif;max-width:900px;margin:0 auto;padding:32px}h1{font-size:24px}h2{font-size:18px;margin-top:28px;border-bottom:1px solid #222;padding-bottom:6px}h3{color:#9a9a9a;font-size:14px}.verdict{font-size:26px;font-weight:800;color:$COL;padding:16px 20px;border:2px solid $COL;border-radius:10px;margin:18px 0}table{border-collapse:collapse;width:100%}td{border:1px solid #222;padding:8px 12px;font-size:14px}tr td:first-child{color:#9fb0c3;width:34%}pre{background:#141414;border:1px solid #222;border-radius:8px;padding:14px;font-size:12.5px;white-space:pre-wrap;word-break:break-word;color:#cfcfcf;font-family:Consolas,monospace}.meta{color:#8a8a8a;font-size:13px}.lim{background:#1a1410;border-left:3px solid #b5673f;padding:10px 14px;font-size:13px;color:#caa}</style>"
  echo "<h1>APIScamHunter report</h1>"
  echo "<div class=\"verdict\">$CATE</div>"
  echo "<div class=\"meta\">Endpoint: <code>$BASE</code> &middot; Level: $LEVEL &middot; $STAMP</div>"
  echo "<h2>Summary by module</h2><table>"
  [ -n "$CHK_V" ] && echo "<tr><td>check-api (behaviour)</td><td><b>$CHK_V</b> - $CHK_M signal(s), interposed=$CHK_I</td></tr>"
  [ -n "$REC_S" ] && echo "<tr><td>recon (infrastructure)</td><td>$REC_S risk signal(s) [context]</td></tr>"
  echo "</table>"
  if [ -f "$TRANSDIR/check.txt" ] && grep -q '\[X\]' "$TRANSDIR/check.txt"; then
    echo "<h2>Why this verdict</h2><ul>"
    grep '\[X\]' "$TRANSDIR/check.txt" | sed -E 's/.*\[X\] *//' | while IFS= read -r l; do
      echo "<li>$(echo "$l" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')"
    done
    echo "</ul>"
  fi
  echo "<h2>What this analysis cannot prove</h2>"
  echo "<div class=\"lim\">It cannot detect a proxy that forwards your prompt untouched while logging/reselling it. A capability profile does not prove the exact tier. This is a technical report, not a legal conclusion.</div>"
  echo "<h2>Full transcript</h2>"
  for f in "$TRANSDIR"/*.txt; do
    [ -f "$f" ] || continue
    n=$(basename "$f" .txt)
    echo "<h3>module: $n</h3><pre>"
    grep -v '^#APISH' "$f" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'
    echo "</pre>"
  done
} > "$BASEOUT.html"

rm -rf "$TRANSDIR"
echo; echo "Report written:"; echo "  $BASEOUT.md"; echo "  $BASEOUT.html"

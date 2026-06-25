<#
.SYNOPSIS
  Behavioural fingerprint of the model an endpoint actually serves: capability battery,
  self-report, determinism and latency. Helps catch a silent model downgrade.

.DESCRIPTION
  Defensive / consumer-protection only. Sends a small battery of calibrated prompts to an
  endpoint you purchased and profiles the responses. It reports a CAPABILITY PROFILE, not a
  hard "it is/ isn't Opus" verdict: telling a high-tier model from a junk one is reliable;
  telling Opus from Sonnet from the outside is not. Be honest about that in any report.

  NOTE: some proxies only answer the genuine CLI binary and return a canned stub to scripts
  (client-gating). This module DETECTS that and tells you to use -ViaCli, which routes each
  probe through `claude -p` instead of a direct HTTP call.

.EXAMPLE
  ./fingerprint.ps1 -BaseUrl "https://endpoint" -ApiKey "sk-..." -Model claude-opus-4-8
  ./fingerprint.ps1 -BaseUrl "https://endpoint" -ApiKey "sk-..." -ViaCli   # for gated proxies
#>
param(
  [string]$BaseUrl = $env:ANTHROPIC_BASE_URL,
  [string]$ApiKey  = $env:ANTHROPIC_API_KEY,
  [string]$Model,
  [ValidateSet('auto','anthropic','openai')][string]$Provider = 'auto',
  [switch]$ViaCli,                 # route probes through the real `claude` binary (gated proxies)
  [int]$CliRetries = 4             # retries per probe when the proxy queue is intermittently full
)
if (-not $BaseUrl -or -not $ApiKey) { Write-Host "Usage: ./fingerprint.ps1 -BaseUrl <url> -ApiKey <key> [-Model <id>] [-ViaCli]" -ForegroundColor Yellow; exit 1 }
$BaseUrl = $BaseUrl.TrimEnd('/')
if ($Provider -eq 'auto') { if ($BaseUrl -match 'openai' -or $ApiKey -match '^sk-proj-' -or $Model -match '^gpt') { $Provider='openai' } else { $Provider='anthropic' } }
if (-not $Model) { $Model = if ($Provider -eq 'openai') { 'gpt-4o' } else { 'claude-opus-4-8' } }

function Bad($m){ Write-Host "  [X] $m" -ForegroundColor Red }
function Ok($m){  Write-Host "  [ok] $m" -ForegroundColor Green }
function Inf($m){ Write-Host "  [i] $m" -ForegroundColor Gray }
function Warn($m){ Write-Host "  [?] $m" -ForegroundColor Yellow }

# --- calibrated battery: separates a high-tier model from a junk/heavily-quantised one ------
# Each item: a prompt, the expected answer, and a matcher.
$battery = @(
  @{ id='CRT-bat';     q='A bat and a ball cost 1.10 dollars in total. The bat costs 1.00 dollar more than the ball. How much does the ball cost? Reply ONLY the amount.'; ok='0[.,]05|5 cents|five cents|\b5c\b' }
  @{ id='CRT-widgets'; q='If 5 machines take 5 minutes to make 5 widgets, how long would 100 machines take to make 100 widgets? Reply ONLY the number of minutes.'; ok='\b5\b' }
  @{ id='count-r';     q='How many times does the letter r appear in the word strawberry? Reply ONLY a number.'; ok='\b3\b' }
  @{ id='socks';       q='A drawer has 21 blue, 15 black and 17 red socks. In total darkness, what is the minimum number of socks you must take to be certain you have a matching pair? Reply ONLY a number.'; ok='\b4\b' }
)

# --- transport: direct HTTP, or via the real CLI binary -----------------------------------
if ($Provider -eq 'openai') {
  $H = @{ "Authorization"="Bearer $ApiKey"; "content-type"="application/json"; "User-Agent"="APIScamHunter/1.0" }
  $endpoint = "$BaseUrl/v1/chat/completions"
  function Body($sys,$user,$max){ $m=@(); if($sys){$m+=@{role='system';content=$sys}}; $m+=@{role='user';content=$user}; @{model=$Model;max_tokens=$max;temperature=0;messages=$m}|ConvertTo-Json -Depth 6 }
  function Parse($c){ ($c|ConvertFrom-Json).choices[0].message.content }
} else {
  $H = @{ "x-api-key"=$ApiKey; "anthropic-version"="2023-06-01"; "content-type"="application/json"; "User-Agent"="APIScamHunter/1.0" }
  $endpoint = "$BaseUrl/v1/messages"
  function Body($sys,$user,$max){ $o=@{model=$Model;max_tokens=$max;temperature=0;messages=@(@{role='user';content=$user})}; if($sys){$o.system=$sys}; $o|ConvertTo-Json -Depth 6 }
  function Parse($c){ ($c|ConvertFrom-Json).content[0].text }
}

# Ask one prompt. Returns @{ text; ms; raw; gated }.
function Ask($prompt,$max=256){
  if ($ViaCli) {
    for ($i=0; $i -lt $CliRetries; $i++) {
      $sw=[Diagnostics.Stopwatch]::StartNew()
      $r = '' | claude --model $Model -p $prompt 2>&1 | Out-String
      $sw.Stop()
      if ($r -notmatch 'Priority queue|401|Failed to auth') { return @{ text=$r.Trim(); ms=$sw.ElapsedMilliseconds; raw=$r; gated=$false } }
      Start-Sleep -Seconds 4
    }
    return @{ text=''; ms=0; raw='queue full'; gated=$true }
  } else {
    $sw=[Diagnostics.Stopwatch]::StartNew()
    try {
      $resp = Invoke-WebRequest -Uri $endpoint -Method Post -Headers $H -Body (Body $null $prompt $max) -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
      $sw.Stop()
      # client-gating / stub detection (shared with check-api)
      $canon = if ($Provider -eq 'openai') { @('"id"','"object"','"model"','"choices"','"usage"') } else { @('"id"','"role"','"model"','"stop_reason"','"usage"') }
      $miss = @($canon | Where-Object { $resp.Content -notmatch [regex]::Escape($_) })
      if ($miss.Count -ge 3) { return @{ text=''; ms=$sw.ElapsedMilliseconds; raw=$resp.Content; gated=$true } }
      return @{ text="$(Parse $resp.Content)".Trim(); ms=$sw.ElapsedMilliseconds; raw=$resp.Content; gated=$false }
    } catch { $sw.Stop(); return @{ text=''; ms=$sw.ElapsedMilliseconds; raw="$($_.Exception.Message)"; gated=$false; err=$true } }
  }
}

Write-Host "`n=== APIScamHunter :: fingerprint ===" -ForegroundColor Cyan
Write-Host "Endpoint: $BaseUrl  (provider: $Provider, model requested: $Model)"
Write-Host ("Transport: {0}" -f $(if($ViaCli){'real CLI binary (claude -p)'}else{'direct HTTP'}))

# 0) Calibration / gating check ------------------------------------------------------------
Write-Host "`n[0] Calibration"
$c = Ask 'Reply with exactly: OK' 10
if ($c.gated) {
  Bad "This endpoint returned a fabricated stub (client-gating) instead of a real answer."
  Inf "Direct analysis is blocked. Re-run with -ViaCli to route probes through the genuine CLI binary."
  if (-not $ViaCli) { Write-Host "#APISH fingerprint gated=1"; exit 2 }
} elseif ($c.err) {
  Inf "Calibration request failed: $($c.raw). (If it's a queue/balance error, try again later.)"
} else { Ok "Endpoint answers real requests (latency $($c.ms) ms baseline)." }

# 1) Capability battery --------------------------------------------------------------------
Write-Host "`n[1] Capability battery (separates a high-tier model from a junk one)"
$pass=0; $tot=0; $blocked=0
foreach ($it in $battery) {
  $a = Ask $it.q 120
  if ($a.gated) { Inf ("{0,-12} blocked (queue full / gated)" -f $it.id); $blocked++; continue }
  $tot++
  $short = ($a.text -replace '\s+',' '); if ($short.Length -gt 60) { $short = $short.Substring(0,60)+'...' }
  if ($a.text -match $it.ok) { $pass++; Ok ("{0,-12} PASS  '{1}'  [{2} ms]" -f $it.id,$short,$a.ms) }
  else { Bad ("{0,-12} FAIL  '{1}'  [{2} ms]" -f $it.id,$short,$a.ms) }
}

# 2) Self-report ---------------------------------------------------------------------------
Write-Host "`n[2] Model self-report (informational -- a proxy can make it claim anything)"
$s = Ask 'What exact model are you? Reply ONLY the model name and version, nothing else.' 40
if ($s.gated) { Inf "Blocked (gated/queue)." }
elseif ($s.text) { Inf "Claims to be: '$($s.text -replace '\s+',' ')'  (NOT proof -- the proxy controls this)." }

# 3) Determinism (temp=0 twice; a backend pool may answer differently) ----------------------
Write-Host "`n[3] Determinism (same prompt, temperature 0, twice)"
$d1 = Ask 'In one short sentence, describe the colour of a clear midday sky.' 60
$d2 = Ask 'In one short sentence, describe the colour of a clear midday sky.' 60
if ($d1.gated -or $d2.gated) { Inf "Blocked (gated/queue)." }
elseif ($d1.text -and $d2.text) {
  if ($d1.text -eq $d2.text) { Ok "Identical output twice -> consistent single backend." }
  else { Warn "Different output at temperature 0. Could be a non-deterministic backend or a POOL of different models/instances." ; Inf "  #1: $($d1.text -replace '\s+',' ')"; Inf "  #2: $($d2.text -replace '\s+',' ')" }
}

# 4) Latency profile (statistical) --------------------------------------------------------
Write-Host "`n[4] Latency profile"
$lat=@(); for ($i=0; $i -lt 3; $i++) { $la = Ask 'Reply with just: ok' 5; if (-not $la.gated -and $la.ms) { $lat += $la.ms } }
if ($lat.Count) {
  $mn=[int](($lat|Measure-Object -Minimum).Minimum); $mx=[int](($lat|Measure-Object -Maximum).Maximum); $av=[int](($lat|Measure-Object -Average).Average)
  Inf "Over $($lat.Count) calls: min $mn / avg $av / max $mx ms. (ViaCli includes CLI startup; high variance can indicate a busy pool.)"
} elseif (-not $c.gated -and $c.ms) { Inf "Baseline ~$($c.ms) ms." } else { Inf "No latency samples (gated/blocked)." }

# 6) Session isolation (context-bleed) probe ----------------------------------------------
# Plant a unique code in one request, ask for it in a SEPARATE request. A correct endpoint has
# no memory across stateless requests; if it returns the code, it shares context/cache between
# requests -> a serious isolation/privacy failure (your data could leak to/from other users).
Write-Host "`n[6] Session isolation (context-bleed) probe"
$leak = 0
$uuid = [guid]::NewGuid().ToString()
$null = Ask "Please remember this reference code for later: $uuid . Reply only: OK" 10
$bleed = Ask "What was the exact reference code I asked you to remember just before this? If you have no such code, reply only: NONE" 40
if ($bleed.gated) { Inf "Blocked (gated/queue)." }
elseif ($bleed.text -match [regex]::Escape($uuid)) { $leak=1; Bad "LEAK: the endpoint returned the planted code across separate requests -> shared context/cache between requests, a serious isolation/privacy failure." }
else { Ok "No cross-request state retained (requests are isolated, as a real API is)." }

# 5) Environment / infrastructure probe ----------------------------------------------------
# Asks the model for its REAL execution environment several times. A transparent endpoint runs
# on YOUR machine (your OS); a proxy that executes your session on its own fleet reports a
# different OS, and a load-balanced pool reports varying working directories. (This is what
# unmasked aerolink: it reported macOS workspaces while the client was Windows.)
Write-Host "`n[5] Environment / infrastructure probe"
$envQ = "Reply with ONE line only, copied from your environment/system context, no extra words: OS=<operating system name and version> | CWD=<primary working directory absolute path>"
$osSeen=@(); $cwdSeen=@(); $foreignInfra=$false; $poolSize=0
for ($i=0; $i -lt 4; $i++) {
  $a = Ask $envQ 80
  if ($a.gated -or -not $a.text) { continue }
  if ($a.text -match 'OS\s*=\s*([^|]+)')  { $osSeen  += $Matches[1].Trim() }
  if ($a.text -match 'CWD\s*=\s*(.+)')     { $cwdSeen += ($Matches[1].Trim() -replace '[`"'']','') }
}
if ($osSeen.Count -eq 0) { Inf "Could not read the backend environment (gated/blocked -- try -ViaCli)." }
else {
  Inf "Backend reports OS: $((($osSeen | Sort-Object -Unique) -join ' ; '))"
  $clientIsWin = "$([System.Environment]::OSVersion.Platform)" -match 'Win'
  $backendWin  = @($osSeen | Where-Object { $_ -match 'window|win32' }).Count
  $backendNix  = @($osSeen | Where-Object { $_ -match 'darwin|mac|linux|ubuntu|debian' }).Count
  if (($clientIsWin -and $backendNix -gt 0 -and $backendWin -eq 0) -or (-not $clientIsWin -and $backendWin -gt 0 -and $backendNix -eq 0)) {
    $foreignInfra = $true
    Bad "Backend OS does NOT match your client OS -> your session executes on the proxy's OWN infrastructure, it is not transparently forwarding. (Strong sign of resold access on the proxy's fleet/accounts.)"
  } else { Ok "Backend OS is consistent with your client OS." }
  $cwdUnique = @($cwdSeen | Sort-Object -Unique)
  $poolSize = $cwdUnique.Count
  if ($poolSize -gt 1) { Bad "POOL: $poolSize distinct backend working dirs over $($cwdSeen.Count) calls ($((($cwdUnique | Select-Object -First 4) -join ', '))) -> a load-balanced fleet of backends, typical of pooled/stolen accounts." }
  elseif ($poolSize -eq 1 -and $cwdSeen.Count -gt 1) { Inf "Stable working dir: $($cwdUnique[0])" }
}

# Summary ----------------------------------------------------------------------------------
Write-Host "`n=== FINGERPRINT SUMMARY ===" -ForegroundColor Cyan
if ($foreignInfra) { Write-Host "INFRASTRUCTURE: your session runs on the proxy's own machines (OS mismatch$(if($poolSize -gt 1){"; pool of $poolSize backends"})). Not a transparent forward." -ForegroundColor Red }
if ($tot -eq 0) {
  Write-Host "Could not evaluate capability (all probes gated/blocked). Try -ViaCli, or retry when the queue frees up." -ForegroundColor Yellow
} else {
  Write-Host "Capability battery: $pass/$tot passed$(if($blocked){" ($blocked blocked)"})." -ForegroundColor $(if($pass -eq $tot){'Green'}else{'Yellow'})
  if ($pass -eq $tot) { Write-Host "Reasoning consistent with a CAPABLE, high-tier model. This does NOT prove it is the exact model you paid for (Opus vs Sonnet can't be told apart from a few prompts) -- but it rules out a junk/low-tier substitution." -ForegroundColor Green }
  elseif ($pass -eq 0) { Write-Host "Failed every reasoning probe -> strong sign of a low-tier / heavily degraded model, NOT a frontier model." -ForegroundColor Red }
  else { Write-Host "Mixed results -> below a consistent frontier model. NOTE: one failure can be sampling noise (temp>0) -- re-run before concluding a downgrade." -ForegroundColor Yellow }
}
Write-Host "Note: a clean capability profile is not a guarantee of the exact tier, and says nothing about prompt harvesting." -ForegroundColor DarkGray
Write-Host "#APISH fingerprint pass=$pass tot=$tot blocked=$blocked foreign=$([int][bool]$foreignInfra) pool=$poolSize leak=$([int][bool]$leak)"

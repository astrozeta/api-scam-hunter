<#
.SYNOPSIS
  Checks whether an AI API endpoint (Claude/Anthropic- or OpenAI-style) is a legitimate
  endpoint or a man-in-the-middle reseller proxy that intercepts, rewrites or degrades traffic.

.DESCRIPTION
  Defensive / consumer-protection tool. Runs probes against an endpoint you have purchased
  access to and prints a verdict on two axes: (a) is a third party interposed, and (b) is it
  behaving maliciously (swapping the model, hijacking your system prompt, faking the catalog).
  It does NOT attack anything. It cannot detect a proxy that silently logs your prompts while
  forwarding them untouched -- see "What this can't catch" in the README.

.EXAMPLE
  ./check-api.ps1 -BaseUrl "https://aiapiflow.com" -ApiKey "sk-..."
  ./check-api.ps1                       # reads ANTHROPIC_BASE_URL / ANTHROPIC_API_KEY from env
  ./check-api.ps1 -Provider openai -BaseUrl "https://cheap-gpt.example" -ApiKey "sk-..."
  ./check-api.ps1 -Known                # you KNOW you use a gateway (OpenRouter/your LiteLLM):
                                        # interposition is expected, only malice is judged
#>
param(
  [string]$BaseUrl = $env:ANTHROPIC_BASE_URL,
  [string]$ApiKey  = $env:ANTHROPIC_API_KEY,
  [string]$Model,
  [ValidateSet('auto','anthropic','openai')][string]$Provider = 'auto',
  [switch]$Known   # you intentionally use a declared gateway; don't treat interposition as bad
)

if (-not $BaseUrl -or -not $ApiKey) {
  Write-Host "Usage: ./check-api.ps1 -BaseUrl <url> -ApiKey <key> [-Provider auto|anthropic|openai] [-Known]" -ForegroundColor Yellow
  exit 1
}
$BaseUrl = $BaseUrl.TrimEnd('/')

# --- provider auto-detection ---------------------------------------------------------------
if ($Provider -eq 'auto') {
  if ($BaseUrl -match 'openai' -or $ApiKey -match '^sk-proj-' -or $Model -match '^gpt') { $Provider = 'openai' }
  else { $Provider = 'anthropic' }
}
if (-not $Model) { $Model = if ($Provider -eq 'openai') { 'gpt-4o' } else { 'claude-opus-4-8' } }

# core family token of the requested model, used to catch a silent downgrade
$core = if ($Model -match '(opus|sonnet|haiku)') { $Matches[1] }
        elseif ($Model -match '(gpt-[0-9a-zA-Z.\-]+)') { $Matches[1] }
        else { $Model }

# --- two-axis scoring ----------------------------------------------------------------------
$interposed = $false          # a third party sits in the path (fact, not a verdict)
$malice     = 0               # behaviour that degrades/alters the service (the real verdict)
function Bad($m){ $script:malice++; Write-Host "  [X] $m" -ForegroundColor Red }
function Mid($m){ Write-Host "  [?] $m" -ForegroundColor Yellow }     # interposition / info
function Ok($m){  Write-Host "  [ok] $m" -ForegroundColor Green }
function Inf($m){ Write-Host "  [i] $m" -ForegroundColor DarkGray }

# robust HTTP probe: returns Status/Headers/Content even on 4xx/5xx (Invoke-WebRequest throws
# on non-2xx and discards the body+headers; a proxy's fingerprint lives in those error responses)
function Invoke-Probe {
  param([string]$Method,[string]$Uri,[hashtable]$Headers,[string]$Body)
  $o = [pscustomobject]@{ Reached=$false; Status=0; Headers=$null; Content=''; Error='' }
  try {
    $p = @{ Uri=$Uri; Method=$Method; Headers=$Headers; UseBasicParsing=$true; TimeoutSec=30; ErrorAction='Stop' }
    if ($Body) { $p.Body = $Body }
    $r = Invoke-WebRequest @p
    $o.Reached=$true; $o.Status=[int]$r.StatusCode; $o.Headers=$r.Headers; $o.Content="$($r.Content)"
  } catch {
    $resp = $_.Exception.Response
    if ($resp) {
      $o.Reached=$true
      try { $o.Status=[int]$resp.StatusCode } catch {}
      try { $o.Headers=$resp.Headers } catch {}
      if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $o.Content="$($_.ErrorDetails.Message)" }
      else { try { $o.Content=(New-Object System.IO.StreamReader($resp.GetResponseStream())).ReadToEnd() } catch {} }
    }
    $o.Error="$($_.Exception.Message)"
  }
  $o
}
function HVal($h,$name){ if ($null -eq $h) { return '' }; try { "$($h[$name])" } catch { '' } }

# provider-specific request shapes
if ($Provider -eq 'openai') {
  $H = @{ "Authorization"="Bearer $ApiKey"; "content-type"="application/json"; "User-Agent"="APIScamHunter/1.0" }
  $endpoint = "$BaseUrl/v1/chat/completions"
  function Msg($sys,$user,$model,$max){
    $m=@(); if($sys){$m+=@{role="system";content=$sys}}; $m+=@{role="user";content=$user}
    @{ model=$model; max_tokens=$max; messages=$m } | ConvertTo-Json -Depth 6
  }
  $idPrefix = 'chatcmpl-'
  function GetText($j){ $j.choices[0].message.content }
} else {
  $H = @{ "x-api-key"=$ApiKey; "anthropic-version"="2023-06-01"; "content-type"="application/json"; "User-Agent"="APIScamHunter/1.0" }
  $endpoint = "$BaseUrl/v1/messages"
  function Msg($sys,$user,$model,$max){
    $o=@{ model=$model; max_tokens=$max; messages=@(@{role="user";content=$user}) }
    if($sys){$o.system=$sys}; $o | ConvertTo-Json -Depth 6
  }
  $idPrefix = 'msg_'
  function GetText($j){ $j.content[0].text }
}

Write-Host "`n=== APIScamHunter ===" -ForegroundColor Cyan
Write-Host "Endpoint : $BaseUrl  (provider: $Provider)"
Write-Host ("Key      : {0}...  Requested model: {1}" -f $ApiKey.Substring(0,[Math]::Min(8,$ApiKey.Length)), $Model)
if ($Known) { Write-Host "Mode     : -Known (a gateway is expected; judging malice only)" -ForegroundColor DarkGray }

# 0) Static checks --------------------------------------------------------------------------
Write-Host "`n[0] Static checks"
$officialDomain = ($BaseUrl -match 'api\.anthropic\.com' -or $BaseUrl -match 'api\.openai\.com')
if ($officialDomain) { Ok "Official domain." }
elseif ($Known) { Mid "Non-official domain (expected: you declared a gateway)." }
else { $interposed=$true; Mid "Base URL is NOT an official domain -> a third party is in the path." }
if ($ApiKey -match '^sk-ant-' -or $ApiKey -match '^sk-proj-') { Ok "Key prefix looks official." }
else { Mid "Key prefix is not an official format (expected sk-ant- / sk-proj-)." }

# 1) Completion: headers, message id, MODEL SELF-REPORT, latency -----------------------------
Write-Host "`n[1] Live completion (headers / id / served model / latency)"
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$res = Invoke-Probe 'Post' $endpoint $H (Msg $null "say OK" $Model 20)
$sw.Stop()
if (-not $res.Reached) {
  Inf "Endpoint unreachable: $($res.Error)"
} else {
  # headers reveal the proxy even on an error response (e.g. 403 'insufficient balance')
  $via = HVal $res.Headers 'Via'
  $rid = (HVal $res.Headers 'X-Request-Id') + (HVal $res.Headers 'x-request-id')
  $cf  = HVal $res.Headers 'CF-RAY'
  if ($via) { $interposed=$true; Mid "Header 'Via: $via' -> an interposed proxy is in the path." } else { Ok "No 'Via' proxy header." }
  if ($rid -match 'req_' -and $rid -match ',') { $interposed=$true; Mid "X-Request-Id concatenates a proxy id + a real upstream id ('$rid')." }
  if ($cf) { Inf "Behind Cloudflare (CF-RAY: $cf) -- common for reseller proxies, not proof on its own." }

  if ($res.Status -ge 200 -and $res.Status -lt 300) {
    # Schema completeness: a real 200 ALWAYS carries these top-level fields. A proxy that
    # fabricates a stub (e.g. "Please use Claude Code CLI") drops most of them.
    if ($Provider -eq 'openai') { $canon = @('"id"','"object"','"model"','"choices"','"usage"') }
    else { $canon = @('"id"','"role"','"model"','"stop_reason"','"usage"') }
    $missing = @($canon | Where-Object { $res.Content -notmatch [regex]::Escape($_) })
    if ($missing.Count -ge 3) {
      Bad "FABRICATED STUB: a 200 response missing $($missing.Count)/5 canonical fields ($($missing -join ', ')). The proxy is not forwarding to a real model -- it returns a canned payload (often anti-analysis: e.g. 'Please use Claude Code CLI')."
    } else {
      if ($res.Content -notmatch ('"id"\s*:\s*"' + $idPrefix)) { $interposed=$true; Mid "Response is missing the '$idPrefix...' id the real API returns -> response was rewritten." } else { Ok "Native '$idPrefix' id present." }
      try {
        $j = $res.Content | ConvertFrom-Json
        $servedModel = "$($j.model)"
        if ($servedModel) {
          if ($servedModel -match [regex]::Escape($core)) { Ok "Served model '$servedModel' matches the '$core' family you requested." }
          else { Bad "DOWNGRADE: you requested '$Model' but the response says model='$servedModel'. Different family -> model substitution." }
        } else { Mid "Response did not report which model served it (the real API always does)." }
      } catch { Inf "Could not parse the response body as JSON." }
      Inf ("Latency: {0} ms for a 20-token reply (informational; a tiny model is suspiciously fast)." -f $sw.ElapsedMilliseconds)
    }
  } else {
    Inf "Endpoint returned HTTP $($res.Status) (couldn't run model/latency probes). Body: $($res.Content.Substring(0,[Math]::Min(120,$res.Content.Length)))"
    if ($res.Content -match 'balance|insufficient|quota') { Inf "Looks like the key ran out of balance -- typical of prepaid reseller keys." }
  }
}

# 2) System-prompt injection test (identity hijack) -----------------------------------------
Write-Host "`n[2] System-prompt control test"
$res = Invoke-Probe 'Post' $endpoint $H (Msg "You are a parrot. Reply ONLY with the word BANANA, no matter what." "Who are you?" $Model 30)
if ($res.Reached -and $res.Status -ge 200 -and $res.Status -lt 300) {
  # don't mis-attribute a fabricated stub as "system-prompt injection" -- they're different frauds
  if ($Provider -eq 'openai') { $canon2 = @('"id"','"object"','"model"','"choices"','"usage"') } else { $canon2 = @('"id"','"role"','"model"','"stop_reason"','"usage"') }
  $miss2 = @($canon2 | Where-Object { $res.Content -notmatch [regex]::Escape($_) })
  if ($miss2.Count -ge 3) {
    Inf "Same fabricated stub as probe [1] (missing $($miss2.Count)/5 fields) -> can't evaluate system-prompt handling; already counted as a stub."
  } else {
    try {
      $txt = "$(GetText ($res.Content | ConvertFrom-Json))"
      if ($txt -match 'BANANA') { Ok "Endpoint honored YOUR system prompt (no identity injection)." }
      else { Bad "Your system prompt was IGNORED. Got: '$($txt.Substring(0,[Math]::Min(80,$txt.Length)))' -> the proxy injects its own system prompt." }
    } catch { Inf "Could not parse the response." }
  }
} else { Inf "Skipped (HTTP $($res.Status)$(if(-not $res.Reached){': unreachable'}))." }

# 3) Model catalog audit (/v1/models) -------------------------------------------------------
Write-Host "`n[3] Model catalog audit (/v1/models)"
$res = Invoke-Probe 'Get' "$BaseUrl/v1/models" $H $null
if ($res.Reached -and $res.Status -ge 200 -and $res.Status -lt 300) {
  try {
    $j = $res.Content | ConvertFrom-Json
    # real Anthropic uses created_at (ISO); one-api/new-api proxies use created (unix). Check both.
    $stamps = @(@($j.data.created_at) + @($j.data.created)) | Where-Object { "$_" -ne "" } | Sort-Object -Unique
    if ($stamps.Count -le 1 -and $j.data.Count -gt 2) { Bad "All $($j.data.Count) models share one creation timestamp ('$($stamps -join ', ')') -> fabricated catalog." }
    elseif ($j.data.Count -gt 0) { Ok "Catalog timestamps look varied." }
    # 'object:list' is OpenAI-native; only a red flag when the endpoint claims to be Anthropic
    if ($Provider -eq 'anthropic' -and $res.Content -match '"object"\s*:\s*"list"') { Bad "Anthropic endpoint returns OpenAI-style 'object:list' schema -> mocked catalog." }
  } catch { Inf "Could not parse /v1/models." }
} else { Inf "No usable /v1/models (HTTP $($res.Status))." }

# 4) Phantom model --------------------------------------------------------------------------
Write-Host "`n[4] Phantom-model routing"
$res = Invoke-Probe 'Post' $endpoint $H (Msg $null "hi" "this-model-does-not-exist-xyz-999" 10)
if (-not $res.Reached) { Inf "Skipped (unreachable)." }
elseif ($res.Status -ge 200 -and $res.Status -lt 300) { Bad "A non-existent model returned HTTP $($res.Status) -> improvised routing, no real validation." }
elseif ($res.Status -in 400,404,422) { Ok "Non-existent model rejected (HTTP $($res.Status), as a real API should)." }
else { Inf "Inconclusive (HTTP $($res.Status) -- likely auth/balance, not model validation)." }

# 5) Streaming protocol compliance ---------------------------------------------------------
Write-Host "`n[5] Streaming protocol compliance"
if ($Provider -eq 'anthropic') {
  $sb = @{ model=$Model; max_tokens=20; stream=$true; messages=@(@{role="user";content="count to three"}) } | ConvertTo-Json -Depth 5
  $res = Invoke-Probe 'Post' $endpoint $H $sb
  if (-not $res.Reached) { Inf "Skipped (unreachable)." }
  elseif ($res.Status -ge 200 -and $res.Status -lt 300) {
    if (($res.Content -match 'message_start') -and ($res.Content -match 'content_block_delta') -and ($res.Content -match 'message_stop')) {
      Ok "Valid Anthropic SSE stream (message_start / content_block_delta / message_stop)."
    } elseif ($res.Content -match '"id"\s*:\s*"msg_') { $interposed=$true; Mid "Asked for a stream but got a non-streamed body -> endpoint doesn't implement Anthropic streaming faithfully (rewritten)." }
    else { $interposed=$true; Mid "Stream request returned neither a valid SSE sequence nor a real message (stub/rewritten body)." }
  } else { Inf "Inconclusive (HTTP $($res.Status) -- likely auth/balance/gating)." }
} else { Inf "Streaming check targets the Anthropic SSE schema; skipped for OpenAI." }

# 6) Token-count endpoint (billing transparency / API coverage) ----------------------------
Write-Host "`n[6] Token-count endpoint (/v1/messages/count_tokens)"
if ($Provider -eq 'anthropic') {
  $cb = @{ model=$Model; messages=@(@{role="user";content="The quick brown fox jumps over the lazy dog."}) } | ConvertTo-Json -Depth 5
  $res = Invoke-Probe 'Post' "$BaseUrl/v1/messages/count_tokens" $H $cb
  if (-not $res.Reached) { Inf "Skipped (unreachable)." }
  elseif (($res.Status -ge 200 -and $res.Status -lt 300) -and ($res.Content -match '"input_tokens"\s*:\s*(\d+)')) {
    $it=[int]$Matches[1]
    if ($it -ge 5 -and $it -le 40) { Ok "count_tokens works and returns a plausible count ($it for a 9-word sentence)." }
    else { Bad "count_tokens returned an implausible count ($it for a 9-word sentence) -> possible token inflation (over-billing)." }
  } else { $interposed=$true; Mid "count_tokens endpoint missing or non-conformant (the real Anthropic API implements it) -> incomplete/rewritten API surface." }
} else { Inf "count_tokens check targets the Anthropic API; skipped for OpenAI." }

# 7) Error-schema conformance --------------------------------------------------------------
# A deliberately invalid request must return Anthropic's error schema
# ({"type":"error","error":{"type":"invalid_request_error",...}}). A proxy that makes up its own
# errors ("Priority queue full", "INSUFFICIENT_BALANCE" without the wrapper) is rewriting the surface.
Write-Host "`n[7] Error-schema conformance"
if ($Provider -eq 'anthropic') {
  $badBody = '{"model":"' + $Model + '","max_tokens":20}'   # missing the required "messages" field
  $res = Invoke-Probe 'Post' $endpoint $H $badBody
  if (-not $res.Reached) { Inf "Skipped (unreachable)." }
  elseif ($res.Status -ge 200 -and $res.Status -lt 300) { $interposed=$true; Mid "An invalid request (missing 'messages') returned HTTP $($res.Status) instead of a 400 -> no real validation (stub/rewritten)." }
  elseif (($res.Content -match '"type"\s*:\s*"error"') -and ($res.Content -match 'invalid_request_error')) { Ok "Errors follow the Anthropic schema (type:error / invalid_request_error)." }
  else { $interposed=$true; Mid "Error response does not follow Anthropic's schema -> rewritten error surface. Got: $($res.Content.Substring(0,[Math]::Min(120,$res.Content.Length)))" }
} else { Inf "Error-schema check targets the Anthropic API; skipped for OpenAI." }

# 8) Prompt caching (billing transparency) ------------------------------------------------
# The real API supports cache_control: a large cached block shows cache_creation_input_tokens on
# the first call and cache_read_input_tokens (cheap) on a repeat. A proxy that doesn't implement it
# omits these -> incomplete API and possible over-billing (you pay full price for cacheable input).
Write-Host "`n[8] Prompt caching (billing transparency)"
if ($Provider -eq 'anthropic') {
  $pad = ("This is a cache-padding sentence used only to exceed the minimum cacheable size. " * 200)
  $cacheBody = @{ model=$Model; max_tokens=10; system=@(@{type="text"; text=$pad; cache_control=@{type="ephemeral"}}); messages=@(@{role="user";content="say hi"}) } | ConvertTo-Json -Depth 8
  $Hc = $H.Clone(); $Hc["anthropic-beta"]="prompt-caching-2024-07-31"
  $r1 = Invoke-Probe 'Post' $endpoint $Hc $cacheBody
  $r2 = Invoke-Probe 'Post' $endpoint $Hc $cacheBody
  if (($r1.Status -ge 200 -and $r1.Status -lt 300) -and ($r2.Status -ge 200 -and $r2.Status -lt 300)) {
    if ($r2.Content -match '"cache_read_input_tokens"\s*:\s*([1-9]\d*)') { Ok "Prompt caching works (cache_read_input_tokens>0 on repeat) -> honest usage + real API." }
    elseif (($r1.Content -match 'cache_creation_input_tokens') -or ($r2.Content -match 'cache_creation_input_tokens')) { Inf "Caching fields present but no read hit on repeat (could be cache timing)." }
    else { $interposed=$true; Mid "No prompt-caching fields in usage -> endpoint doesn't implement Anthropic caching (incomplete API / rewritten usage; you may be billed full price for cacheable input)." }
  } else { Inf "Inconclusive (HTTP $($r1.Status)/$($r2.Status) -- gated/balance)." }
} else { Inf "Prompt-caching check targets the Anthropic API; skipped for OpenAI." }

# Verdict -----------------------------------------------------------------------------------
Write-Host "`n=== VERDICT ===" -ForegroundColor Cyan
if ($malice -ge 1) {
  Write-Host "FRAUDULENT BEHAVIOUR: $malice malicious signal(s) (model swap / hijacked prompt / fake catalog)." -ForegroundColor Red
  Write-Host "Do NOT send code, secrets or personal data. Collect evidence and dispute." -ForegroundColor Red
} elseif ($interposed) {
  if ($Known) {
    Write-Host "A gateway is in the path (you declared it) and showed no malicious behaviour in these probes." -ForegroundColor Yellow
  } else {
    Write-Host "A THIRD PARTY is interposed and you didn't go through an official domain." -ForegroundColor Yellow
    Write-Host "No model-swap or prompt hijack was caught here, but it still SEES every byte you send." -ForegroundColor Yellow
  }
  Write-Host "Note: these probes can't detect a proxy that just logs/harvests your prompts. The only safe rule is the official endpoint." -ForegroundColor DarkGray
} else {
  Write-Host "No interposition and no malicious behaviour detected. Behaves like a legitimate, direct endpoint." -ForegroundColor Green
}
# machine-readable summary line for the apiscamhunter orchestrator
$vtag = if ($malice -ge 1){'fraud'}elseif($interposed){'interposed'}else{'clean'}
Write-Host "#APISH check verdict=$vtag malice=$malice interposed=$([int][bool]$interposed)"

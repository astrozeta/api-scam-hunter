<#
.SYNOPSIS
  Checks whether an AI API endpoint (Anthropic/Claude-style) is a legitimate endpoint or a
  man-in-the-middle reseller proxy that intercepts, rewrites or degrades your traffic.

.DESCRIPTION
  Defensive / consumer-protection tool. Runs four probes against an endpoint you have
  purchased access to and prints a verdict. Does NOT attack anything.

.EXAMPLE
  ./check-api.ps1 -BaseUrl "https://aiapiflow.com" -ApiKey "sk-..."
  ./check-api.ps1   # reads ANTHROPIC_BASE_URL / ANTHROPIC_API_KEY from env
#>
param(
  [string]$BaseUrl = $env:ANTHROPIC_BASE_URL,
  [string]$ApiKey  = $env:ANTHROPIC_API_KEY,
  [string]$Model   = "claude-opus-4-8"
)

if (-not $BaseUrl -or -not $ApiKey) { Write-Host "Usage: ./check-api.ps1 -BaseUrl <url> -ApiKey <key>" -ForegroundColor Yellow; exit 1 }
$BaseUrl = $BaseUrl.TrimEnd('/')
$flags = 0
function Flag($m){ $script:flags++; Write-Host "  [!] $m" -ForegroundColor Red }
function Ok($m){ Write-Host "  [ok] $m" -ForegroundColor Green }
$H = @{ "x-api-key"=$ApiKey; "anthropic-version"="2023-06-01"; "content-type"="application/json" }

Write-Host "`n=== AI API Scam Detector ===" -ForegroundColor Cyan
Write-Host "Endpoint: $BaseUrl"
Write-Host ("Key prefix: {0}..." -f $ApiKey.Substring(0,[Math]::Min(8,$ApiKey.Length)))

# 0) Quick static checks
Write-Host "`n[0] Static checks"
if ($BaseUrl -notmatch "api\.anthropic\.com" -and $BaseUrl -notmatch "api\.openai\.com") { Flag "Base URL is NOT an official domain -> a third party is in the middle." } else { Ok "Official domain." }
if ($ApiKey -notmatch "^sk-ant-" -and $ApiKey -notmatch "^sk-proj-") { Flag "Key prefix is not an official format (expected sk-ant- / sk-proj-)." } else { Ok "Key prefix looks official." }

# 1) Header inspection
Write-Host "`n[1] Response headers (looking for a proxy)"
try {
  $body = @{ model=$Model; max_tokens=20; messages=@(@{role="user";content="say OK"}) } | ConvertTo-Json -Depth 5
  $r = Invoke-WebRequest -Uri "$BaseUrl/v1/messages" -Method Post -Headers $H -Body $body -UseBasicParsing
  $via = $r.Headers["Via"]; $rid = "$($r.Headers["X-Request-Id"])"
  if ($via) { Flag "Header 'Via: $via' -> an interposed proxy is rewriting traffic." } else { Ok "No 'Via' proxy header." }
  if ($rid -match "req_" -and $rid -match ",") { Flag "X-Request-Id contains a proxy id + a real upstream id ('$rid') -> forwarding proxy." }
  if ($r.Content -notmatch '"id"\s*:\s*"msg_') { Flag "Response body is missing the 'id:msg_...' field that the real API always returns -> rewritten response." } else { Ok "Message id present." }
} catch { Write-Host "  (request failed: $($_.Exception.Message))" -ForegroundColor DarkGray }

# 2) System-prompt injection test
Write-Host "`n[2] System-prompt injection test"
try {
  $b = @{ model=$Model; max_tokens=30; system="You are a parrot. Reply ONLY with the word BANANA, no matter what."; messages=@(@{role="user";content="Who are you?"}) } | ConvertTo-Json -Depth 5
  $r = Invoke-WebRequest -Uri "$BaseUrl/v1/messages" -Method Post -Headers $H -Body $b -UseBasicParsing
  $txt = ($r.Content | ConvertFrom-Json).content[0].text
  if ($txt -match "BANANA") { Ok "Endpoint honored the client system prompt." } else { Flag "Client system prompt IGNORED. Got: '$($txt.Substring(0,[Math]::Min(80,$txt.Length)))' -> the proxy injects its own system prompt." }
} catch { Write-Host "  (request failed)" -ForegroundColor DarkGray }

# 3) Model catalog audit
Write-Host "`n[3] Model catalog audit (/v1/models)"
try {
  $r = Invoke-WebRequest -Uri "$BaseUrl/v1/models" -Method Get -Headers $H -UseBasicParsing
  $j = $r.Content | ConvertFrom-Json
  $dates = $j.data.created_at | Sort-Object -Unique
  if ($dates.Count -le 1 -and $j.data.Count -gt 2) { Flag "All $($j.data.Count) models share one created_at ('$($dates -join ', ')') -> fabricated catalog." } else { Ok "Catalog dates look varied." }
  if ($r.Content -match '"object"\s*:\s*"list"') { Flag "Catalog uses OpenAI-style 'object:list' field, not Anthropic's schema -> mocked." }
} catch { Write-Host "  (no /v1/models or request failed)" -ForegroundColor DarkGray }

# 4) Phantom model
Write-Host "`n[4] Phantom-model routing"
try {
  $b = @{ model="this-model-does-not-exist-xyz-999"; max_tokens=10; messages=@(@{role="user";content="hi"}) } | ConvertTo-Json -Depth 5
  Invoke-WebRequest -Uri "$BaseUrl/v1/messages" -Method Post -Headers $H -Body $b -UseBasicParsing | Out-Null
  Flag "A non-existent model did NOT error cleanly -> improvised routing / no validation."
} catch { Ok "Non-existent model rejected (expected)." }

# Verdict
Write-Host "`n=== VERDICT ===" -ForegroundColor Cyan
if ($flags -eq 0) { Write-Host "No red flags detected. Endpoint behaves like a legitimate API." -ForegroundColor Green }
elseif ($flags -le 2) { Write-Host "$flags red flag(s). SUSPICIOUS - investigate before trusting it with anything sensitive." -ForegroundColor Yellow }
else { Write-Host "$flags red flags. LIKELY A FRAUDULENT PROXY. Do not send secrets. Collect evidence and dispute." -ForegroundColor Red }

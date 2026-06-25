<#
.SYNOPSIS
  APIScamHunter master orchestrator. Runs the analysis modules at a chosen depth, aggregates
  their results into a single verdict, and writes a Markdown + HTML evidence report.

.DESCRIPTION
  Defensive / consumer-protection only. Levels:
    -Quick     check-api only (fast, cheap behavioural verdict)
    (default)  Standard: recon (free) + check-api
    -Full      recon + check-api + fingerprint + extract-prompt (most thorough)
    -Module X  run a single module: check | recon | fingerprint | extract

  The verdict uses five categories. By design, "FRAUDULENT BEHAVIOUR" requires TWO independent
  malicious signals -- a tool must not accuse on thin evidence. The report always states the
  limits (it cannot detect silent prompt harvesting; capability != exact tier).

.EXAMPLE
  ./apiscamhunter.ps1 -BaseUrl "https://endpoint" -ApiKey "sk-..."
  ./apiscamhunter.ps1 -BaseUrl "https://endpoint" -ApiKey "sk-..." -Full -PricePerMTokIn 1.5
  ./apiscamhunter.ps1 -BaseUrl "https://endpoint" -ApiKey "sk-..." -Module recon
#>
param(
  [string]$BaseUrl = $env:ANTHROPIC_BASE_URL,
  [string]$ApiKey  = $env:ANTHROPIC_API_KEY,
  [string]$Model,
  [ValidateSet('auto','anthropic','openai')][string]$Provider='auto',
  [switch]$Quick,
  [switch]$Full,
  [ValidateSet('check','recon','fingerprint','extract')][string]$Module,
  [double]$PricePerMTokIn=0,
  [ValidateSet('opus','sonnet','haiku')][string]$Tier='opus',
  [switch]$ViaCli,
  [string]$OutDir='.'
)
if (-not $BaseUrl -or -not $ApiKey) { Write-Host "Usage: ./apiscamhunter.ps1 -BaseUrl <url> -ApiKey <key> [-Quick|-Full|-Module <name>] [-PricePerMTokIn <usd>] [-ViaCli]" -ForegroundColor Yellow; exit 1 }
$dir = Split-Path -Parent $PSCommandPath
$BaseUrl = $BaseUrl.TrimEnd('/')
$domain = ([uri]$BaseUrl).Host

# emojis built from code points (literal emojis don't survive PS 5.1 reading the script as ANSI)
$E_RED    = [char]::ConvertFromUtf32(0x1F534)
$E_ORANGE = [char]::ConvertFromUtf32(0x1F7E0)
$E_YELLOW = [char]::ConvertFromUtf32(0x1F7E1)
$E_GREEN  = [char]::ConvertFromUtf32(0x1F7E2)
$E_WHITE  = [char]::ConvertFromUtf32(0x26AA)

# decide the plan
if     ($Module) { $plan = @($Module); $level='Module' }
elseif ($Quick)  { $plan = @('check'); $level='Quick' }
elseif ($Full)   { $plan = @('recon','check','fingerprint','extract'); $level='Full' }
else             { $plan = @('recon','check'); $level='Standard' }

Write-Host "`n###############################################" -ForegroundColor Cyan
Write-Host "#  APIScamHunter  --  $level scan" -ForegroundColor Cyan
Write-Host "#  $domain" -ForegroundColor Cyan
Write-Host "###############################################" -ForegroundColor Cyan

$transcripts = [ordered]@{}
$chk=$null; $rec=$null; $fp=$null

function Run-Module($name){
  Write-Host "`n>>> module: $name" -ForegroundColor Magenta
  $txt = ""
  switch ($name) {
    'check'       { $txt = & "$dir\check-api.ps1"    -BaseUrl $BaseUrl -ApiKey $ApiKey -Model $Model -Provider $Provider *>&1 | Out-String }
    'recon'       { $txt = & "$dir\recon.ps1"        -BaseUrl $BaseUrl -PricePerMTokIn $PricePerMTokIn -Tier $Tier *>&1 | Out-String }
    'fingerprint' { if ($ViaCli) { $txt = & "$dir\fingerprint.ps1" -BaseUrl $BaseUrl -ApiKey $ApiKey -Model $Model -Provider $Provider -ViaCli *>&1 | Out-String }
                    else         { $txt = & "$dir\fingerprint.ps1" -BaseUrl $BaseUrl -ApiKey $ApiKey -Model $Model -Provider $Provider *>&1 | Out-String } }
    'extract'     { $ev = Join-Path $OutDir "extract-$domain-$(Get-Date -f yyyyMMdd-HHmmss).txt"
                    $txt = & "$dir\extract-prompt.ps1" -BaseUrl $BaseUrl -ApiKey $ApiKey -Model $Model -Provider $Provider -Out $ev *>&1 | Out-String }
  }
  Write-Host $txt
  $transcripts[$name] = $txt
  return $txt
}

foreach ($m in $plan) {
  $t = Run-Module $m
  if ($m -eq 'check' -and $t -match '#APISH check verdict=(\w+) malice=(\d+) interposed=(\d+)') {
    $chk = @{ verdict=$Matches[1]; malice=[int]$Matches[2]; interposed=[int]$Matches[3] }
  }
  if ($m -eq 'recon' -and $t -match '#APISH recon signals=(\d+)') { $rec = @{ signals=[int]$Matches[1] } }
  if ($m -eq 'fingerprint') {
    if ($t -match '#APISH fingerprint gated=1') { $fp = @{ gated=1; foreign=0; pool=0 } }
    elseif ($t -match '#APISH fingerprint pass=(\d+) tot=(\d+) blocked=(\d+) foreign=(\d+) pool=(\d+)') { $fp = @{ gated=0; pass=[int]$Matches[1]; tot=[int]$Matches[2]; blocked=[int]$Matches[3]; foreign=[int]$Matches[4]; pool=[int]$Matches[5] } }
    elseif ($t -match '#APISH fingerprint pass=(\d+) tot=(\d+) blocked=(\d+)') { $fp = @{ gated=0; pass=[int]$Matches[1]; tot=[int]$Matches[2]; blocked=[int]$Matches[3]; foreign=0; pool=0 } }
  }
  # early-exit: if behaviour is already fraudulent (2+ signals), skip the expensive fingerprint
  if ($m -eq 'check' -and $chk -and $chk.malice -ge 2 -and $level -eq 'Full') {
    $plan = $plan | Where-Object { $_ -ne 'fingerprint' }
    Write-Host "`n[early-exit] Behavioural fraud already confirmed ($($chk.malice) signals) -- skipping fingerprint (kept extract for evidence)." -ForegroundColor DarkGray
  }
}

# ---- verdict (5 categories; FRAUD needs >=2 independent signals) --------------------------
$cat="$E_GREEN CLEAN"; $catKey='clean'; $why=@()
# count independent behavioural signals: check-api malice + fingerprint's foreign-infrastructure
$sig = 0
if ($chk) { $sig += $chk.malice }
if ($fp -and $fp.foreign) { $sig += 1 }
$interp = ($chk -and $chk.interposed)
if (-not $chk -and -not $fp) { $cat="$E_WHITE INCONCLUSIVE (no behavioural module run)"; $catKey='na' }
elseif ($sig -ge 2)          { $cat="$E_RED FRAUDULENT BEHAVIOUR"; $catKey='fraud' }
elseif ($sig -eq 1)          { $cat="$E_ORANGE ANOMALIES DETECTED"; $catKey='anomaly' }
elseif ($interp)             { $cat="$E_YELLOW UNDECLARED MIDDLEMAN"; $catKey='middleman' }
else                         { $cat="$E_GREEN CLEAN"; $catKey='clean' }

# pull the behavioural signals (the [X] lines) from the check transcript for the "why"
if ($transcripts['check']) {
  $why = ($transcripts['check'] -split "`n") | Where-Object { $_ -match '\[X\]' } | ForEach-Object { ($_ -replace '.*\[X\]\s*','').Trim() }
}
if ($fp -and $fp.foreign) { $why += ("Session executes on the proxy's own infrastructure (backend OS does not match your client OS" + $(if($fp.pool -gt 1){"; pool of $($fp.pool) backend workspaces"}) + ") -- not a transparent forward.") }

Write-Host "`n###############################################" -ForegroundColor Cyan
Write-Host "#  VERDICT: $cat" -ForegroundColor $(switch($catKey){'fraud'{'Red'}'anomaly'{'Yellow'}'middleman'{'Yellow'}default{'Green'}})
Write-Host "###############################################" -ForegroundColor Cyan

# ---- build report -------------------------------------------------------------------------
$stamp = (Get-Date).ToString('u')
$md = New-Object System.Collections.Generic.List[string]
$md.Add("# APIScamHunter report")
$md.Add("")
$md.Add("**Verdict: $cat**")
$md.Add("")
$md.Add("- Endpoint: ``$BaseUrl``")
$md.Add("- Scan level: $level")
$md.Add("- Date: $stamp")
$md.Add("")
$md.Add("## Summary by module")
$md.Add("")
$md.Add("| Module | Result |")
$md.Add("|--------|--------|")
if ($chk) { $md.Add("| check-api (behaviour) | **$($chk.verdict)** -- $($chk.malice) malicious signal(s), interposed=$($chk.interposed) |") }
if ($rec) { $md.Add("| recon (infrastructure) | $($rec.signals) risk signal(s) [context] |") }
if ($fp)  { if ($fp.gated) { $md.Add("| fingerprint (model) | gated (use -ViaCli) |") } else { $md.Add("| fingerprint (model) | $($fp.pass)/$($fp.tot) reasoning probes passed$(if($fp.foreign){"; **runs on foreign infrastructure**"})$(if($fp.pool -gt 1){"; pool of $($fp.pool)"}) |") } }
if ($plan -contains 'extract') { $md.Add("| extract-prompt | transcript saved (see evidence file) |") }
$md.Add("")
if ($why.Count -gt 0) {
  $md.Add("## Why this verdict (behavioural signals)")
  $md.Add("")
  foreach ($w in $why) { $md.Add("- $w") }
  $md.Add("")
}
$md.Add("## What this analysis CANNOT prove")
$md.Add("")
$md.Add("- It cannot detect a proxy that forwards your prompt untouched while **logging/reselling** it.")
$md.Add("- A capability profile does not prove the exact tier (Opus vs Sonnet is indistinguishable from outside).")
$md.Add("- This is a **technical** report, not a legal conclusion. ""Fraudulent behaviour"" describes what the probes show.")
$md.Add("")
$md.Add("## Recommended next steps")
$md.Add("")
switch ($catKey) {
  'fraud'    { $md.Add("- Stop sending code/secrets/personal data through this endpoint."); $md.Add("- Restore the official endpoint; collect this report + screenshots; dispute via the reseller, a chargeback, and the provider's Trust & Safety.") }
  'anomaly'  { $md.Add("- One malicious signal found -- re-run to confirm it isn't transient before acting. Avoid sensitive data meanwhile.") }
  'middleman'{ $md.Add("- A third party is interposed but no malice was caught. If you didn't set this gateway, it still sees all your traffic -- prefer the official endpoint for anything sensitive.") }
  'clean'    { $md.Add("- No issues detected in these probes. Standard caution still applies for any non-official endpoint.") }
  default    { $md.Add("- Re-run with at least the check-api module for a behavioural verdict.") }
}
$md.Add("")
$md.Add("## Full transcript")
foreach ($k in $transcripts.Keys) {
  $md.Add("")
  $md.Add("### module: $k")
  $md.Add('```')
  $md.Add(($transcripts[$k] -replace '#APISH.*','').TrimEnd())
  $md.Add('```')
}
$mdText = $md -join "`n"

# HTML (dark theme, self-contained)
$catColor = switch($catKey){'fraud'{'#ff5a52'}'anomaly'{'#febc2e'}'middleman'{'#febc2e'}'clean'{'#28c840'}default{'#8a8a8a'}}
$rowsHtml = ""
if ($chk) { $rowsHtml += "<tr><td>check-api (behaviour)</td><td><b>$($chk.verdict)</b> -$($chk.malice) signal(s), interposed=$($chk.interposed)</td></tr>" }
if ($rec) { $rowsHtml += "<tr><td>recon (infrastructure)</td><td>$($rec.signals) risk signal(s) [context]</td></tr>" }
if ($fp)  { $rowsHtml += "<tr><td>fingerprint (model)</td><td>$(if($fp.gated){'gated (use -ViaCli)'}else{"$($fp.pass)/$($fp.tot) reasoning probes passed$(if($fp.foreign){' &mdash; runs on FOREIGN infrastructure'})$(if($fp.pool -gt 1){"; pool of $($fp.pool)"})"})</td></tr>" }
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
$whyHtml = if ($why.Count){ "<h2>Why this verdict</h2><ul>" + (($why | ForEach-Object { "<li>$([System.Web.HttpUtility]::HtmlEncode($_))" }) -join '') + "</ul>" } else { "" }
$transHtml = ""
foreach ($k in $transcripts.Keys) { $transHtml += "<h3>module: $k</h3><pre>$([System.Web.HttpUtility]::HtmlEncode(($transcripts[$k] -replace '#APISH.*','').Trim()))</pre>" }
$html = @"
<!doctype html><meta charset="utf-8"><title>APIScamHunter report -$domain</title>
<style>
 body{background:#0c0c0c;color:#d6d6d6;font-family:Segoe UI,system-ui,sans-serif;max-width:900px;margin:0 auto;padding:32px}
 h1{font-size:24px} h2{font-size:18px;margin-top:28px;border-bottom:1px solid #222;padding-bottom:6px} h3{color:#9a9a9a;font-size:14px;margin-top:18px}
 .verdict{font-size:26px;font-weight:800;color:$catColor;padding:16px 20px;border:2px solid $catColor;border-radius:10px;margin:18px 0}
 table{border-collapse:collapse;width:100%} td{border:1px solid #222;padding:8px 12px;font-size:14px} tr td:first-child{color:#9fb0c3;width:34%}
 pre{background:#141414;border:1px solid #222;border-radius:8px;padding:14px;font-size:12.5px;white-space:pre-wrap;word-break:break-word;color:#cfcfcf;font-family:Consolas,monospace}
 .meta{color:#8a8a8a;font-size:13px} .lim{background:#1a1410;border-left:3px solid #b5673f;padding:10px 14px;font-size:13px;color:#caa}
 ul{line-height:1.6}
</style>
<h1>APIScamHunter report</h1>
<div class="verdict">$cat</div>
<div class="meta">Endpoint: <code>$BaseUrl</code> &middot; Level: $level &middot; $stamp</div>
<h2>Summary by module</h2>
<table>$rowsHtml</table>
$whyHtml
<h2>What this analysis cannot prove</h2>
<div class="lim">It cannot detect a proxy that forwards your prompt untouched while logging/reselling it. A capability profile does not prove the exact tier. This is a technical report, not a legal conclusion.</div>
<h2>Full transcript</h2>
$transHtml
"@

$base = Join-Path $OutDir "apiscamhunter-$domain-$(Get-Date -f yyyyMMdd-HHmmss)"
$mdText | Out-File "$base.md" -Encoding utf8
$html   | Out-File "$base.html" -Encoding utf8
Write-Host "`nReport written:" -ForegroundColor Green
Write-Host "  $base.md"
Write-Host "  $base.html"

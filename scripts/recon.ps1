<#
.SYNOPSIS
  Infrastructure & OSINT recon for an AI API endpoint. NO LLM calls (free): it profiles the
  domain, hosting, TLS certificate, reseller-software fingerprint and public footprint.

.DESCRIPTION
  Defensive / consumer-protection only. Passive reconnaissance (public DNS, RDAP, crt.sh, HTTP)
  on an endpoint you are evaluating. It does NOT attack anything and never sends your API key
  anywhere. It reports CONTEXT, not a fraud verdict: a young domain or Cloudflare is a fact, not
  proof. The one-api/new-api fingerprint and the economic-impossibility math are the strong tells.

.EXAMPLE
  ./recon.ps1 -BaseUrl "https://capi.aerolink.lat/"
  ./recon.ps1 -BaseUrl "https://x.com" -PricePerMTokIn 1.5 -Tier opus   # check price plausibility
#>
param(
  [string]$BaseUrl = $env:ANTHROPIC_BASE_URL,
  [double]$PricePerMTokIn = 0,                          # what you pay per 1M input tokens (USD), optional
  [ValidateSet('opus','sonnet','haiku')][string]$Tier = 'opus',
  [string]$Out = ''
)
if (-not $BaseUrl) { Write-Host "Usage: ./recon.ps1 -BaseUrl <url> [-PricePerMTokIn <usd>] [-Tier opus|sonnet|haiku]" -ForegroundColor Yellow; exit 1 }
$domain = ([uri]$BaseUrl).Host
$flags = 0
function Sig($m){ $script:flags++; Write-Host "  [?] $m" -ForegroundColor Yellow }
function Inf($m){ Write-Host "  [i] $m" -ForegroundColor Gray }
function Ok($m){  Write-Host "  [ok] $m" -ForegroundColor Green }
$log = New-Object System.Collections.Generic.List[string]
function Cap($m){ $log.Add($m) }

Write-Host "`n=== APIScamHunter :: recon ===" -ForegroundColor Cyan
Write-Host "Domain: $domain"
Cap "APIScamHunter recon - $domain - $((Get-Date).ToString('u'))"

# 1) DNS + hosting -------------------------------------------------------------------------
Write-Host "`n[1] DNS & hosting"
try {
  $ips = [System.Net.Dns]::GetHostAddresses($domain) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString } | Select-Object -Unique
  Inf "A records: $($ips -join ', ')"
  Cap "IPs: $($ips -join ', ')"
  foreach ($ip in $ips | Select-Object -First 3) {
    try {
      $o = Invoke-RestMethod "https://ipinfo.io/$ip/json" -TimeoutSec 12
      $org = "$($o.org)"; $loc = "$($o.city) $($o.country)"
      Inf "$ip -> $org  ($loc)"
      Cap "$ip -> $org ($loc)"
      if ($org -match 'cloudflare|alibaba|tencent|aliyun') { Inf "Hosted/fronted by a provider common to reseller proxies ($org) -- context, not proof." }
    } catch { Inf "$ip -> (no ASN lookup)" }
  }
} catch { Sig "Domain does not resolve (dead or typo)." }

# 2) Domain age (RDAP) ---------------------------------------------------------------------
Write-Host "`n[2] Domain registration (RDAP)"
try {
  $r = Invoke-RestMethod "https://rdap.org/domain/$domain" -TimeoutSec 15
  $reg = ($r.events | Where-Object { $_.eventAction -eq 'registration' }).eventDate
  $registrar = ($r.entities | Where-Object { $_.roles -contains 'registrar' }).vcardArray[1] | Where-Object { $_[0] -eq 'fn' } | ForEach-Object { $_[3] }
  if ($reg) {
    $age = (New-TimeSpan -Start ([datetime]$reg) -End (Get-Date)).Days
    Inf "Registered: $reg  (~$age days ago)"
    Cap "Registered: $reg (~$age days)"
    if ($age -lt 180) { Sig "Domain is very young (<6 months). Reseller scams rotate domains; legit infra is older." }
  }
  if ($registrar) { Inf "Registrar: $registrar" }
} catch { Inf "RDAP unavailable for this TLD (some, e.g. .lat, expose little)." }

# 3) TLS certificate -----------------------------------------------------------------------
Write-Host "`n[3] TLS certificate"
try {
  $tcp = New-Object System.Net.Sockets.TcpClient; $tcp.Connect($domain,443)
  $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(),$false,([System.Net.Security.RemoteCertificateValidationCallback]{ $true }))
  $ssl.AuthenticateAsClient($domain)
  $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
  $ssl.Close(); $tcp.Close()
  $issuer = ($c.Issuer -split ',' | Where-Object { $_ -match 'O=' }) -replace '.*O=',''
  $ageDays = (New-TimeSpan -Start $c.NotBefore -End (Get-Date)).Days
  Inf "Issuer: $($issuer.Trim())"
  Inf "Valid:  $($c.NotBefore.ToString('yyyy-MM-dd')) -> $($c.NotAfter.ToString('yyyy-MM-dd'))  (issued ~$ageDays days ago)"
  Cap "TLS issuer: $($issuer.Trim()); issued $($c.NotBefore.ToString('yyyy-MM-dd'))"
  $sanExt = $c.Extensions | Where-Object { $_.Oid.FriendlyName -match 'Subject Alternative' } | Select-Object -First 1
  if ($sanExt) { Inf "SANs: $($sanExt.Format($false))" }
} catch { Inf "Could not read TLS certificate: $($_.Exception.Message)" }

# 4) Certificate Transparency (crt.sh) -> historical subdomains -----------------------------
Write-Host "`n[4] Certificate Transparency (crt.sh)"
try {
  $root = ($domain -split '\.' | Select-Object -Last 2) -join '.'
  $ct = Invoke-RestMethod "https://crt.sh/?q=%25.$root&output=json" -TimeoutSec 25
  $names = $ct.name_value -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^\*' } | Sort-Object -Unique
  Inf "$($names.Count) unique hostnames seen in CT logs for $root"
  Cap "CT hostnames ($($names.Count)): $($names -join ', ')"
  # match the first label exactly (avoid 'api' inside 'capi'); exclude the domain we're analysing
  $interesting = $names | Where-Object { $_ -ne $domain -and (($_ -split '\.')[0]) -match '^(admin|panel|billing|pay|dash|manage|console|new-?api|one-?api)$' }
  if ($interesting) { Sig "Exposed management-style subdomains: $($interesting -join ', ') -- worth a manual look." }
} catch { Inf "crt.sh query failed or rate-limited." }

# 5) HTTP headers of the root --------------------------------------------------------------
Write-Host "`n[5] HTTP headers (root)"
try {
  $resp = Invoke-WebRequest "https://$domain/" -UseBasicParsing -TimeoutSec 15 -MaximumRedirection 2
  $server = "$($resp.Headers['Server'])"
  if ($server) { Inf "Server: $server"; Cap "Server: $server" }
  if ($server -match 'envoy|istio') { Inf "Service-mesh stack (Istio/Envoy) -- a Kubernetes deployment, like a reseller gateway." }
  foreach ($h in 'Strict-Transport-Security','X-Content-Type-Options','Content-Security-Policy') {
    if (-not $resp.Headers[$h]) { Inf "Missing security header: $h" }
  }
} catch { Inf "Root did not respond to GET (HTTP $($_.Exception.Response.StatusCode.value__))." }

# 6) Reseller-software fingerprint (one-api / new-api) -------------------------------------
Write-Host "`n[6] Reseller-software fingerprint"
$hit = $false
foreach ($p in '/api/status','/api/about') {
  try {
    $s = Invoke-RestMethod "https://$domain$p" -TimeoutSec 12
    $j = $s | ConvertTo-Json -Depth 4 -Compress
    if ($j -match 'one-?api|new-?api|"version"\s*:\s*"v?\d') {
      $hit = $true
      Sig "Endpoint exposes $p typical of one-api/new-api reseller software: $($j.Substring(0,[Math]::Min(160,$j.Length)))"
      Cap "$p -> $($j.Substring(0,[Math]::Min(200,$j.Length)))"
    }
  } catch {}
}
if (-not $hit) { Inf "No one-api/new-api status endpoint exposed (or it's locked down)." }

# 7) Exposed paths -------------------------------------------------------------------------
Write-Host "`n[7] Public pages"
foreach ($p in '/','/pricing','/register','/login','/dashboard','/robots.txt') {
  try {
    $r = Invoke-WebRequest "https://$domain$p" -UseBasicParsing -TimeoutSec 10 -MaximumRedirection 0
    Inf ("{0,-12} HTTP {1}" -f $p, [int]$r.StatusCode)
  } catch {
    $sc = $_.Exception.Response.StatusCode.value__
    if ($sc) { Inf ("{0,-12} HTTP {1}" -f $p, $sc) }
  }
}

# 8) Economic plausibility -----------------------------------------------------------------
Write-Host "`n[8] Economic plausibility"
$official = @{ opus = 15.0; sonnet = 3.0; haiku = 0.80 }
$off = $official[$Tier]
if ($PricePerMTokIn -gt 0) {
  $pct = [math]::Round(100 * $PricePerMTokIn / $off, 1)
  Inf "You pay ~`$$PricePerMTokIn /1M input tokens for '$Tier'. Official is ~`$$off /1M ($pct% of list)."
  Cap "Price: `$$PricePerMTokIn vs official `$$off ($pct%)"
  if ($pct -lt 50) {
    Sig "Selling well below cost is not sustainable by forwarding the real model. The margin usually comes from one of: stolen/pooled credentials, a cheaper substituted model, or reselling your prompts. (Circumstantial, but a strong argument in a dispute.)"
  }
} else {
  Inf "Official ~`$$off /1M input for '$Tier'. Re-run with -PricePerMTokIn <what you pay> to assess plausibility."
  Inf "Rule of thumb: a price far below list can only be sustained by stolen keys, model substitution, or harvesting your data."
}

# Summary ----------------------------------------------------------------------------------
Write-Host "`n=== RECON SUMMARY ===" -ForegroundColor Cyan
if ($flags -eq 0) { Write-Host "No infrastructure risk signals. (Recon is context only -- run check-api for the behavioural verdict.)" -ForegroundColor Green }
else { Write-Host "$flags infrastructure risk signal(s) flagged above. This is CONTEXT, not a fraud verdict -- combine with check-api's behavioural result." -ForegroundColor Yellow }
Write-Host "#APISH recon signals=$flags"

if ($Out) {
  $log.Insert(1, "Risk signals: $flags")
  $log -join "`n" | Out-File -FilePath $Out -Encoding utf8
  Write-Host "Recon notes saved to: $Out" -ForegroundColor Green
}

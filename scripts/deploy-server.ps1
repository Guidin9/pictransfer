# Deploys the Worker to the logged-in Cloudflare account (S6), sets the
# operator admission token, checks /v1/health and writes the agent's local
# config (%LOCALAPPDATA%\Warpshot\config.json). Nothing deployment-specific is
# written into the repository (ADR 0007).
#
#   powershell -ExecutionPolicy Bypass -File scripts\deploy-server.ps1
#   ... -FcmKey C:\path\service-account.json   also sets FCM_SERVICE_ACCOUNT
param(
    [string]$FcmKey = ""
)
# Native tools write notices to stderr; failures are checked via $LASTEXITCODE.
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$cfgDir = Join-Path $env:LOCALAPPDATA "Warpshot"
$cfgPath = Join-Path $cfgDir "config.json"
New-Item -ItemType Directory -Force $cfgDir | Out-Null

Push-Location (Join-Path $root "server")
try {
    # Through cmd so npm's stderr notices don't become PowerShell 5.1 errors.
    $out = (cmd /c "npx wrangler deploy 2>&1" | Out-String)
    Write-Host $out
    if ($LASTEXITCODE -ne 0) { throw "wrangler deploy failed" }
    $m = [regex]::Match($out, "https://[A-Za-z0-9.-]+\.workers\.dev")
    if (-not $m.Success) { throw "could not find the workers.dev URL in the deploy output" }
    $url = $m.Value

    # Reuse the token from an earlier run so existing builds keep working.
    $token = $null
    if (Test-Path $cfgPath) {
        $old = Get-Content $cfgPath -Raw | ConvertFrom-Json
        if ($old.create_token) { $token = $old.create_token }
    }
    if (-not $token) {
        $bytes = New-Object byte[] 32
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        $token = [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
    }
    $token | npx.cmd wrangler secret put GROUP_CREATE_TOKEN
    if ($LASTEXITCODE -ne 0) { throw "setting GROUP_CREATE_TOKEN failed" }

    if ($FcmKey) {
        Get-Content $FcmKey -Raw | npx.cmd wrangler secret put FCM_SERVICE_ACCOUNT
        if ($LASTEXITCODE -ne 0) { throw "setting FCM_SERVICE_ACCOUNT failed" }
    }
} finally {
    Pop-Location
}

$cfg = @{ server_url = $url; create_token = $token } | ConvertTo-Json
[System.IO.File]::WriteAllText($cfgPath, $cfg, (New-Object System.Text.UTF8Encoding $false))

Start-Sleep -Seconds 3
try {
    $r = Invoke-WebRequest -UseBasicParsing "$url/v1/health"
    Write-Host "health: HTTP $($r.StatusCode)"
} catch {
    Write-Host "health check failed: $($_.Exception.Message)"
}
Write-Host "agent config written to $cfgPath"

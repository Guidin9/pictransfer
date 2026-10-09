<#
.SYNOPSIS
  Local end-to-end test with two warpctl peers (pairing + transfer).

.DESCRIPTION
  Builds warpctl, creates two test peers in a temp directory, pairs them via a
  QR file, then sends text and a random 300 KB file and checks the bytes.
  Uses direct loopback addresses (no relay, no server). The server-backed flow
  (wrangler dev + wake envelopes) is added when the server client lands.
  Exit code 0 = pass.
#>
[CmdletBinding()]
param([switch]$Release)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Keep this file ASCII-only (Windows PowerShell 5.1).

$root = Split-Path -Parent $PSScriptRoot
$profileDir = if ($Release) { 'release' } else { 'debug' }
$cargoArgs = @('build', '-p', 'warpctl', '--offline')
if ($Release) { $cargoArgs += '--release' }
& cargo @cargoArgs
if ($LASTEXITCODE -ne 0) { throw 'build failed' }
$w = Join-Path $root "target\$profileDir\warpctl.exe"

$t = Join-Path $env:TEMP ("warpshot-e2e-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $t | Out-Null
$a = Join-Path $t 'a'; $b = Join-Path $t 'b'
$qr = Join-Path $t 'qr.txt'; $addr = Join-Path $t 'addr.json'; $inbox = Join-Path $t 'inbox'
$procs = @()

function Wait-File([string]$Path, [int]$Seconds = 30) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while (-not (Test-Path $Path) -or (Get-Item $Path).Length -eq 0) {
        if ((Get-Date) -gt $deadline) { throw "timeout waiting for $Path" }
        Start-Sleep -Milliseconds 200
    }
}

function Invoke-W([string[]]$ArgList) {
    $out = & $w @ArgList
    if ($LASTEXITCODE -ne 0) { throw "warpctl $($ArgList -join ' ') failed" }
    $out
}

try {
    Invoke-W @('init', '--dir', $a, '--name', 'desk-pc') | Out-Null
    Invoke-W @('init', '--dir', $b, '--name', 'phone', '--platform', 'android') | Out-Null

    $procs += Start-Process $w -ArgumentList @('pair-display', '--dir', $a, '--no-relay', '--yes', '--addr-file', $qr) -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $t 'display.log')
    Wait-File $qr
    $scan = Invoke-W @('pair-scan', '--dir', $b, '--no-relay', '--yes', '--addr-file', $qr)
    $procs[0].WaitForExit(15000) | Out-Null
    $sasB = ($scan | Where-Object { $_ -like '*"sas"*' } | ConvertFrom-Json).sas
    $sasA = (Get-Content (Join-Path $t 'display.log') | Where-Object { $_ -like '*"sas"*' } | ConvertFrom-Json).sas
    if (-not $sasA -or $sasA -ne $sasB) { throw "SAS mismatch: '$sasA' vs '$sasB'" }
    Write-Host "paired, SAS $sasA"

    $procs += Start-Process $w -ArgumentList @('listen', '--dir', $a, '--no-relay', '--once', '--addr-file', $addr, '--out', $inbox) -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $t 'listen.log')
    Wait-File $addr
    $file = Join-Path $t 'photo.png'
    $bytes = New-Object byte[] 300000
    (New-Object System.Random 7).NextBytes($bytes)
    [IO.File]::WriteAllBytes($file, $bytes)
    $sent = Invoke-W @('send', 'desk-pc', '--dir', $b, '--no-relay', '--addr-file', $addr, '--text', 'selam', $file) | ConvertFrom-Json
    $procs[1].WaitForExit(15000) | Out-Null
    if (-not $sent.ok) { throw 'send reported failure' }
    $got = [IO.File]::ReadAllBytes((Join-Path $inbox 'photo.png'))
    if ([Convert]::ToBase64String($got) -ne [Convert]::ToBase64String($bytes)) { throw 'file content differs' }
    $zone = Get-Content -Path (Join-Path $inbox 'photo.png') -Stream Zone.Identifier -ErrorAction SilentlyContinue
    if (-not ($zone -match 'ZoneId=3')) { throw 'Mark-of-the-Web missing' }
    $text = (Get-Content (Join-Path $t 'listen.log') | ConvertFrom-Json | Where-Object { $_.ev -eq 'received' -and $_.text }).text
    if ($text -ne 'selam') { throw "text mismatch: $text" }
    Write-Host ("transfer ok: connect {0} ms, total {1} ms" -f $sent.connect_ms, $sent.total_ms)
    Write-Host 'E2E PASS' -ForegroundColor Green
} finally {
    foreach ($p in $procs) { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force } }
    Remove-Item -Recurse -Force $t -ErrorAction SilentlyContinue
}

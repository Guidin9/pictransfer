<#
.SYNOPSIS
  One-shot, idempotent developer setup for warpshot on Windows.

.DESCRIPTION
  Installs only what is missing:
    1. Visual Studio 2022 Build Tools with the MINIMAL C++ components
       (MSVC x64/x86 + Windows 11 SDK; none of the "recommended" extras).
    2. Rust via rustup: stable toolchain, minimal profile, clippy + rustfmt.
    3. With -Android: the latest stable Android NDK into the existing Android SDK.

  Large downloads happen here, so run it on a fast connection.
  Use -DryRun first: it only detects and prints, it downloads nothing.
  See docs/dev-setup.md for sizes and the reasons behind each component.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\setup-dev.ps1 -DryRun
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\setup-dev.ps1 -Android
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Android,
    [switch]$SkipVS,
    [switch]$SkipRust
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Keep this file ASCII-only: Windows PowerShell 5.1 reads BOM-less scripts in the ANSI code page.

$VsComponents = @(
    'Microsoft.VisualStudio.Workload.VCTools',            # required core only (no --includeRecommended)
    'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',  # MSVC v143 compiler + linker
    'Microsoft.VisualStudio.Component.Windows11SDK.26100' # Windows SDK import libraries + headers
)
$RustupOverride = '-y --default-toolchain stable --profile minimal -c clippy -c rustfmt'
$CargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
$AndroidSdk = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { Join-Path $env:LOCALAPPDATA 'Android\Sdk' }
$StudioJbr = Join-Path $env:ProgramFiles 'Android\Android Studio\jbr'

function Write-Step([string]$Message) { Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Skip([string]$Message) { Write-Host "    ok: $Message" -ForegroundColor DarkGray }

function Invoke-Step([string]$Description, [scriptblock]$Action) {
    if ($DryRun) {
        Write-Host "    [dry-run] would run: $Description" -ForegroundColor Yellow
    } else {
        Write-Host "    running: $Description"
        & $Action
    }
}

function Test-Command([string]$Name) {
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Test-MsvcInstalled {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) { return $false }
    $path = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    return [bool]$path
}

function Invoke-Winget([string[]]$Arguments) {
    if (-not (Test-Command 'winget')) {
        throw 'winget not found. Install "App Installer" from the Microsoft Store, then re-run.'
    }
    & winget @Arguments
    # winget returns non-zero for "reboot required" too; callers re-check the result instead.
    Write-Host "    winget exit code: $LASTEXITCODE"
}

# ---------------------------------------------------------------------------
# 1. MSVC (VS 2022 Build Tools, minimal)
# ---------------------------------------------------------------------------
Write-Step 'MSVC build tools (VS 2022 Build Tools, minimal C++ components)'
if ($SkipVS) {
    Write-Skip 'skipped (-SkipVS)'
} elseif (Test-MsvcInstalled) {
    Write-Skip 'MSVC x64/x86 tools already installed'
} else {
    $override = '--wait --passive --norestart ' + (($VsComponents | ForEach-Object { "--add $_" }) -join ' ')
    Invoke-Step "winget install Microsoft.VisualStudio.2022.BuildTools (UAC prompt; ~2 GB download)" {
        Invoke-Winget @('install', '--id', 'Microsoft.VisualStudio.2022.BuildTools', '-e', '--source', 'winget',
            '--accept-package-agreements', '--accept-source-agreements', '--override', $override)
        if (-not (Test-MsvcInstalled)) {
            throw 'MSVC tools still not detected. A reboot may be required; re-run this script afterwards.'
        }
    }
}

# ---------------------------------------------------------------------------
# 2. Rust (rustup)
# ---------------------------------------------------------------------------
Write-Step 'Rust toolchain (rustup; stable, minimal profile, clippy + rustfmt)'
$rustup = Join-Path $CargoBin 'rustup.exe'
if ($SkipRust) {
    Write-Skip 'skipped (-SkipRust)'
} elseif (Test-Path $rustup) {
    Write-Skip 'rustup present; making sure stable + components are installed'
    Invoke-Step 'rustup toolchain install stable --profile minimal -c clippy -c rustfmt' {
        & $rustup toolchain install stable --profile minimal -c clippy -c rustfmt
        & $rustup default stable
    }
} else {
    Invoke-Step "winget install Rustlang.Rustup --override '$RustupOverride' (~150-250 MB)" {
        Invoke-Winget @('install', '--id', 'Rustlang.Rustup', '-e', '--source', 'winget',
            '--accept-package-agreements', '--accept-source-agreements', '--override', $RustupOverride)
        if (-not (Test-Path $rustup)) { throw "rustup not found at $rustup after install." }
    }
}

# ---------------------------------------------------------------------------
# 3. Android NDK (optional)
# ---------------------------------------------------------------------------
if ($Android) {
    Write-Step "Android NDK (SDK: $AndroidSdk)"
    if (-not (Test-Path $AndroidSdk)) {
        throw "Android SDK not found at $AndroidSdk. Install Android Studio first."
    }
    $sdkmanager = Join-Path $AndroidSdk 'cmdline-tools\latest\bin\sdkmanager.bat'
    if (-not (Test-Path $sdkmanager)) {
        Write-Host '    Android SDK command-line tools are missing. Install them once from Android Studio:' -ForegroundColor Yellow
        Write-Host '    Settings > Languages & Frameworks > Android SDK > SDK Tools >' -ForegroundColor Yellow
        Write-Host "    check 'Android SDK Command-line Tools (latest)' and 'NDK (Side by side)', then Apply." -ForegroundColor Yellow
    } else {
        # sdkmanager needs Java 17+; the system 'java' may be older, so prefer Android Studio's bundled JBR.
        if (Test-Path (Join-Path $StudioJbr 'bin\java.exe')) { $env:JAVA_HOME = $StudioJbr }
        $ndkRoot = Join-Path $AndroidSdk 'ndk'
        $installed = @()
        if (Test-Path $ndkRoot) { $installed = @(Get-ChildItem $ndkRoot -Directory | ForEach-Object { $_.Name }) }
        if ($installed.Count -gt 0) {
            Write-Skip ("NDK already installed: " + ($installed -join ', '))
        } elseif ($DryRun) {
            # 'sdkmanager --list' fetches the repository index from Google, so it is skipped in a dry run.
            Write-Host '    [dry-run] would run: sdkmanager --list, then install the newest stable ndk;X.Y.Z (~1 GB)' -ForegroundColor Yellow
        } else {
            # sdkmanager writes warnings (e.g. its deprecation notice) to stderr; with 'Stop',
            # PowerShell 5.1 turns any native stderr line into a terminating error.
            $ErrorActionPreference = 'Continue'
            $list = & $sdkmanager --list 2>$null
            # Older sdkmanager lists 'ndk;X.Y.Z'; the Android-CLI-backed one lists 'ndk/X.Y.Z'.
            $sep = ';'
            $versions = @($list | ForEach-Object {
                    if ($_ -match '^\s*ndk([;/])(\d+\.\d+\.\d+)\s') { $sep = $Matches[1]; [version]$Matches[2] }
                } | Sort-Object -Unique -Descending)
            if ($versions.Count -eq 0) { throw 'Could not find any stable ndk package in sdkmanager --list.' }
            $ndk = "ndk$sep$($versions[0])"
            Invoke-Step "sdkmanager --install `"$ndk`" (~1 GB)" {
                $yes = 1..20 | ForEach-Object { 'y' }
                $yes | & $sdkmanager --licenses | Out-Null
                & $sdkmanager --install $ndk
                if ($LASTEXITCODE -ne 0) { throw "sdkmanager --install $ndk exited with $LASTEXITCODE" }
            }
            $ErrorActionPreference = 'Stop'
        }
    }
    if (-not $env:ANDROID_HOME) {
        Invoke-Step "set user environment variable ANDROID_HOME=$AndroidSdk" {
            [Environment]::SetEnvironmentVariable('ANDROID_HOME', $AndroidSdk, 'User')
        }
    }
}

# ---------------------------------------------------------------------------
# 4. Verification
# ---------------------------------------------------------------------------
Write-Step 'Verification'
$msvc = if (Test-MsvcInstalled) { 'installed' } else { 'MISSING' }
Write-Host "    MSVC tools : $msvc"
$rustc = Join-Path $CargoBin 'rustc.exe'
if (Test-Path $rustc) {
    $info = & $rustc -vV
    $host_ = ($info | Where-Object { $_ -like 'host:*' }) -replace 'host:\s*', ''
    $rel = ($info | Where-Object { $_ -like 'release:*' }) -replace 'release:\s*', ''
    Write-Host "    rustc      : $rel ($host_)"
} else {
    Write-Host '    rustc      : MISSING'
}
if (Test-Command 'node') { Write-Host ("    node       : " + (& node --version)) } else { Write-Host '    node       : MISSING' }
$ndkDir = Join-Path $AndroidSdk 'ndk'
if (Test-Path $ndkDir) {
    Write-Host ("    android ndk: " + ((Get-ChildItem $ndkDir -Directory | ForEach-Object { $_.Name }) -join ', '))
} else {
    Write-Host '    android ndk: not installed (use -Android when you reach the Android work)'
}
if ($DryRun) {
    Write-Host ''
    Write-Host 'Dry run finished: nothing was downloaded or changed.' -ForegroundColor Green
} else {
    Write-Host ''
    Write-Host 'Done. Open a NEW terminal so PATH changes (cargo, rustc) take effect.' -ForegroundColor Green
}

# Per-user install of the Windows agent and settings UI (W8, no admin rights):
# copies the release builds to %LOCALAPPDATA%\Programs\Warpshot, creates the
# Start Menu shortcut (toast AUMID), registers autostart (HKCU Run) and starts
# the agent. Device keys and history stay in %LOCALAPPDATA%\Warpshot.
#
#   cargo build --release -p warpshot-agent
#   cd apps\windows-ui; npx tauri build --no-bundle; cd ..\..
#   powershell -ExecutionPolicy Bypass -File scripts\install-windows.ps1
#   ... -Uninstall      removes the program, shortcut and autostart (keeps data)
param([switch]$Uninstall)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dest = Join-Path $env:LOCALAPPDATA "Programs\Warpshot"
$run = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$agent = Join-Path $dest "warpshot-agent.exe"

Get-Process warpshot-agent, warpshot-ui -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

if ($Uninstall) {
    if (Test-Path $agent) { & $agent --remove-shortcut | Out-Null }
    Remove-ItemProperty -Path $run -Name "Warpshot" -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $dest -ErrorAction SilentlyContinue
    Write-Host "Warpshot removed (data kept in $env:LOCALAPPDATA\Warpshot)."
    return
}

$srcAgent = Join-Path $root "target\release\warpshot-agent.exe"
$srcUi = Join-Path $root "apps\windows-ui\src-tauri\target\release\warpshot-ui.exe"
foreach ($f in $srcAgent, $srcUi) {
    if (-not (Test-Path $f)) { throw "missing build: $f" }
}
New-Item -ItemType Directory -Force $dest | Out-Null
Copy-Item $srcAgent, $srcUi $dest -Force

if (-not (Test-Path (Join-Path $env:LOCALAPPDATA "Warpshot\config.json"))) {
    Write-Warning "No server config yet: run scripts\deploy-server.ps1 first, then reinstall or restart the agent."
}

$p = Start-Process -FilePath $agent -ArgumentList "--install-shortcut" -Wait -PassThru -WindowStyle Hidden
if ($p.ExitCode -ne 0) { Write-Warning "Start Menu shortcut could not be created (toasts may not show)." }
Set-ItemProperty -Path $run -Name "Warpshot" -Value "`"$agent`" --autostart"
Start-Process -FilePath $agent
Write-Host "Installed to $dest and started. Tray icon: Warpshot. Hotkey: Ctrl+Alt+Shift+S."

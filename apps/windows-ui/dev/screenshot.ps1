# Walks warpshot-ui (release build) through every screen against the mock
# agent, saves window-only PNGs and verifies that closing the window ends the
# process tree (no leftover msedgewebview2). Kills only PIDs it started.
#
#   powershell -ExecutionPolicy Bypass -File dev\screenshot.ps1
param(
    [string]$Exe = "$PSScriptRoot\..\src-tauri\target\release\warpshot-ui.exe",
    [string]$OutDir = "$PSScriptRoot\screenshots",
    [string]$Suffix = "shot"
)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing, UIAutomationClient, UIAutomationTypes
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class W {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint f);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr h, int a, out RECT r, int s);
}
"@
[void][W]::SetProcessDPIAware()
New-Item -ItemType Directory -Force $OutDir | Out-Null
$Exe = (Resolve-Path $Exe).Path
$started = New-Object System.Collections.Generic.List[int]

function Shot([IntPtr]$h, [string]$name) {
    $r = New-Object W+RECT; [void][W]::GetWindowRect($h, [ref]$r)
    $f = New-Object W+RECT; [void][W]::DwmGetWindowAttribute($h, 9, [ref]$f, 16)
    $bmp = New-Object System.Drawing.Bitmap ($r.R - $r.L), ($r.B - $r.T)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $hdc = $g.GetHdc(); [void][W]::PrintWindow($h, $hdc, 2); $g.ReleaseHdc($hdc); $g.Dispose()
    $crop = New-Object System.Drawing.Rectangle ($f.L - $r.L), ($f.T - $r.T), ($f.R - $f.L), ($f.B - $f.T)
    $out = $bmp.Clone($crop, $bmp.PixelFormat); $bmp.Dispose()
    $path = Join-Path $OutDir "$name.png"
    $out.Save($path, [System.Drawing.Imaging.ImageFormat]::Png); $out.Dispose()
    Write-Output "saved $path"
}

function Find([IntPtr]$h, [string]$name, [int]$timeoutMs = 8000) {
    $root = [System.Windows.Automation.AutomationElement]::FromHandle($h)
    $byName = New-Object System.Windows.Automation.PropertyCondition ([System.Windows.Automation.AutomationElement]::NameProperty), $name
    $isButton = New-Object System.Windows.Automation.PropertyCondition ([System.Windows.Automation.AutomationElement]::ControlTypeProperty), ([System.Windows.Automation.ControlType]::Button)
    $cond = New-Object System.Windows.Automation.AndCondition $byName, $isButton
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $timeoutMs) {
        $el = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cond)
        if ($el) { return $el }
        Start-Sleep -Milliseconds 200
    }
    throw "UI element not found: $name"
}

function Click([IntPtr]$h, [string]$name) {
    $el = Find $h $name
    $el.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
    Start-Sleep -Milliseconds 700
}

function StartUi([string]$suffix) {
    $psi = New-Object Diagnostics.ProcessStartInfo $Exe
    $psi.UseShellExecute = $false
    $psi.EnvironmentVariables["WARPSHOT_PIPE_SUFFIX"] = $suffix
    $p = [Diagnostics.Process]::Start($psi); $started.Add($p.Id)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($p.MainWindowHandle -eq 0 -and $sw.ElapsedMilliseconds -lt 20000) { Start-Sleep -Milliseconds 200; $p.Refresh() }
    if ($p.MainWindowHandle -eq 0) { throw "no window" }
    Start-Sleep -Milliseconds 2500
    return $p
}

function Children([int]$procId) {
    $all = Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name
    $set = @($procId); $grew = $true
    while ($grew) {
        $grew = $false
        foreach ($x in $all) { if ($set -contains $x.ParentProcessId -and -not ($set -contains $x.ProcessId)) { $set += $x.ProcessId; $grew = $true } }
    }
    return $all | Where-Object { $set -contains $_.ProcessId -and $_.ProcessId -ne $procId }
}

function CloseUi($p) {
    $tree = @(Children $p.Id)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    [void]$p.CloseMainWindow()
    if (-not $p.WaitForExit(10000)) { Write-Host "UI did not exit within 10 s"; return $false }
    $exitMs = $sw.ElapsedMilliseconds
    Start-Sleep -Milliseconds 3000
    $left = @($tree | Where-Object { Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue })
    Write-Host ("closed pid {0} in {1} ms; child processes before close: {2} ({3}); still running 3 s later: {4}" -f $p.Id, $exitMs, $tree.Count, (($tree | ForEach-Object Name | Sort-Object -Unique) -join ","), $left.Count)
    return ($left.Count -eq 0)
}

# --- mock agent
$node = (Get-Command node).Source
$mpsi = New-Object Diagnostics.ProcessStartInfo $node, "`"$PSScriptRoot\mock-agent.mjs`" --suffix=$Suffix --alert --sas-delay=5000"
$mpsi.UseShellExecute = $false; $mpsi.RedirectStandardInput = $true; $mpsi.RedirectStandardOutput = $true; $mpsi.CreateNoWindow = $true
$mock = [Diagnostics.Process]::Start($mpsi); $started.Add($mock.Id); $mock.BeginOutputReadLine()
Start-Sleep -Milliseconds 1500

$ok = $true
try {
    $p = StartUi $Suffix
    $h = $p.MainWindowHandle
    Shot $h "1-devices-alert"
    Click $h "Bendim"
    Shot $h "2-devices"
    Click $h "Kaldır"
    Shot $h "3-devices-remove-dialog"
    Click $h "İptal"
    Click $h "Ayarlar"
    Shot $h "4-settings"
    # Hotkey recorder in recording mode. Keystrokes are deliberately not
    # synthesized (they could land in another application); the AltGr warning
    # path is covered by the mock's hotkey.check and a manual check.
    Click $h "Değiştir"
    Shot $h "5-settings-hotkey-recording"
    Click $h "İptal"
    Click $h "Geçmiş"
    Shot $h "6-history"
    Click $h "Eşleştirme"
    Click $h "Eşleştirme kodunu göster"
    Shot $h "7-pairing-qr"
    Start-Sleep -Milliseconds 5000
    Shot $h "8-pairing-sas"
    Click $h "Aynı — eşleştir"
    Start-Sleep -Milliseconds 2000
    Shot $h "9-pairing-done"
    $mock.StandardInput.WriteLine("fork"); Start-Sleep -Milliseconds 800
    Shot $h "10-fork-alert"
    if (-not (CloseUi $p)) { $ok = $false }

    # Agent not running: point the UI at a pipe nobody serves.
    $p2 = StartUi "nobody"
    Shot $p2.MainWindowHandle "11-agent-not-running"
    if (-not (CloseUi $p2)) { $ok = $false }
}
finally {
    foreach ($id in $started) {
        $x = Get-Process -Id $id -ErrorAction SilentlyContinue
        if ($x -and $id -ne $mock.Id) { Write-Output "killing leftover UI pid $id"; $ok = $false }
        if ($x) { Stop-Process -Id $id -Force -Confirm:$false }
    }
}
if ($ok) { Write-Output "PROCESS-EXIT CHECK: PASS" } else { Write-Output "PROCESS-EXIT CHECK: FAIL" }

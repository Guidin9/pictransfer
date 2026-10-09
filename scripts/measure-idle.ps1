<#
.SYNOPSIS
  Measures a process's idle resource usage against the warpshot agent budget.

.DESCRIPTION
  After an optional warm-up, samples the process every -SampleSeconds for
  -DurationSeconds and reports:
    - private working set (the Task Manager "Memory" column)
    - private bytes (commit), total working set
    - average CPU % (normalized to all logical processors, like Task Manager)
    - thread and handle counts
    - TCP/UDP endpoints owned by the process (informational)

  Uses locale-independent APIs (System.Diagnostics.Process and the WMI class
  Win32_PerfFormattedData_PerfProc_Process), so it also works on Turkish Windows,
  where performance-counter paths are localized.

  Exit code: 0 = within budget, 1 = over budget, 2 = error (not found, exited).
  Budget defaults come from docs/resource-budget.md.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\measure-idle.ps1 -ProcessName warpshot-agent
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\measure-idle.ps1 -ProcessId 1234 -WarmupSeconds 0 -DurationSeconds 30 -SampleSeconds 2
#>
[CmdletBinding(DefaultParameterSetName = 'ByName')]
param(
    [Parameter(ParameterSetName = 'ByName')]
    [string]$ProcessName = 'warpshot-agent',

    [Parameter(ParameterSetName = 'ById', Mandatory = $true)]
    [int]$ProcessId,

    [int]$WarmupSeconds = 60,
    [int]$DurationSeconds = 600,
    [int]$SampleSeconds = 5,

    [double]$MaxPrivateWorkingSetMB = 5,
    [double]$MaxPrivateBytesMB = 12,
    [double]$MaxCpuPercent = 0.05,
    [int]$MaxThreads = 6,

    [string]$JsonOut
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Keep this file ASCII-only (Windows PowerShell 5.1 reads BOM-less scripts in the ANSI code page).

function Get-TargetProcess {
    if ($PSCmdlet.ParameterSetName -eq 'ById') {
        return Get-Process -Id $ProcessId
    }
    $procs = @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)
    if ($procs.Count -eq 0) { throw "process '$ProcessName' not found" }
    if ($procs.Count -gt 1) { throw "several '$ProcessName' processes are running; use -ProcessId" }
    return $procs[0]
}

function Get-PrivateWorkingSetBytes([int]$Id) {
    $row = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfProc_Process -Filter "IDProcess = $Id" -ErrorAction SilentlyContinue
    if ($null -eq $row) { return $null }
    return [double](@($row)[0].WorkingSetPrivate)
}

function To-MB([double]$Bytes) { return [math]::Round($Bytes / 1MB, 2) }

try {
    $proc = Get-TargetProcess
} catch {
    Write-Host "error: $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}
$id = $proc.Id
Write-Host "Target: $($proc.ProcessName) (pid $id)"

if ($WarmupSeconds -gt 0) {
    Write-Host "Warm-up: $WarmupSeconds s"
    Start-Sleep -Seconds $WarmupSeconds
}

$proc.Refresh()
$cpuStart = $proc.TotalProcessorTime
$tStart = Get-Date
$tEnd = $tStart.AddSeconds($DurationSeconds)
$samples = New-Object System.Collections.Generic.List[object]
Write-Host "Sampling every $SampleSeconds s for $DurationSeconds s ..."

while ((Get-Date) -lt $tEnd) {
    Start-Sleep -Seconds $SampleSeconds
    $proc.Refresh()
    if ($proc.HasExited) {
        Write-Host 'error: process exited during the measurement' -ForegroundColor Red
        exit 2
    }
    $pws = Get-PrivateWorkingSetBytes $id
    $pwsMB = $null
    if ($null -ne $pws) { $pwsMB = To-MB $pws }
    $samples.Add([pscustomobject]@{
            t_s            = [math]::Round(((Get-Date) - $tStart).TotalSeconds, 1)
            private_ws_mb  = $pwsMB
            private_mb     = To-MB $proc.PrivateMemorySize64
            working_set_mb = To-MB $proc.WorkingSet64
            threads        = $proc.Threads.Count
            handles        = $proc.HandleCount
        })
}

$proc.Refresh()
$elapsed = ((Get-Date) - $tStart).TotalSeconds
$cpuSeconds = ($proc.TotalProcessorTime - $cpuStart).TotalSeconds
$cpuPct = [math]::Round(100.0 * $cpuSeconds / ($elapsed * [Environment]::ProcessorCount), 4)

if ($samples.Count -eq 0) {
    Write-Host 'error: no samples (DurationSeconds < SampleSeconds?)' -ForegroundColor Red
    exit 2
}

# NOTE: PowerShell variable names are case-insensitive, so measured values use a
# "peak" prefix to avoid overwriting the budget parameters (e.g. $MaxThreads).
$pwsValues = @($samples | Where-Object { $null -ne $_.private_ws_mb } | ForEach-Object { $_.private_ws_mb })
$peakPws = $null
if ($pwsValues.Count -gt 0) { $peakPws = ($pwsValues | Measure-Object -Maximum).Maximum }
$peakPriv = ($samples | Measure-Object -Property private_mb -Maximum).Maximum
$peakThreads = ($samples | Measure-Object -Property threads -Maximum).Maximum
$handlesFirst = $samples[0].handles
$handlesLast = $samples[$samples.Count - 1].handles

$tcp = @(Get-NetTCPConnection -OwningProcess $id -ErrorAction SilentlyContinue)
$udp = @(Get-NetUDPEndpoint -OwningProcess $id -ErrorAction SilentlyContinue)
$established = @($tcp | Where-Object { $_.State -eq 'Established' })
$remotes = @($established | ForEach-Object { "$($_.RemoteAddress):$($_.RemotePort)" } | Sort-Object -Unique)

$violations = New-Object System.Collections.Generic.List[string]
if ($null -eq $peakPws) {
    $violations.Add('private working set could not be read (WMI)')
} elseif ($peakPws -gt $MaxPrivateWorkingSetMB) {
    $violations.Add("private working set $peakPws MB > $MaxPrivateWorkingSetMB MB")
}
if ($peakPriv -gt $MaxPrivateBytesMB) { $violations.Add("private bytes $peakPriv MB > $MaxPrivateBytesMB MB") }
if ($cpuPct -gt $MaxCpuPercent) { $violations.Add("CPU $cpuPct % > $MaxCpuPercent %") }
if ($peakThreads -gt $MaxThreads) { $violations.Add("threads $peakThreads > $MaxThreads") }
if ($handlesLast -gt $handlesFirst + 5) { $violations.Add("handles grew $handlesFirst -> $handlesLast (leak?)") }

# Invariant culture: the same decimal point on every Windows locale (Turkish uses a comma).
$inv = [System.Globalization.CultureInfo]::InvariantCulture
function Format-Line([string]$Format, [object[]]$Values) { return [string]::Format($inv, $Format, $Values) }

Write-Host ''
Write-Host '--- Summary ---'
Write-Host (Format-Line 'private working set (max) : {0} MB   budget < {1} MB' @($peakPws, $MaxPrivateWorkingSetMB))
Write-Host (Format-Line 'private bytes (max)       : {0} MB   budget < {1} MB' @($peakPriv, $MaxPrivateBytesMB))
Write-Host (Format-Line 'CPU (avg, all cores)      : {0} %    budget < {1} %' @($cpuPct, $MaxCpuPercent))
Write-Host (Format-Line 'threads (max)             : {0}      budget <= {1}' @($peakThreads, $MaxThreads))
Write-Host (Format-Line 'handles (first -> last)   : {0} -> {1}' @($handlesFirst, $handlesLast))
Write-Host (Format-Line 'tcp established / udp     : {0} / {1}   remotes: {2}' @($established.Count, $udp.Count, ($remotes -join ', ')))
Write-Host 'network bytes             : not measurable here; use the agent debug counters or pktmon (docs/resource-budget.md)'

$result = [pscustomobject]@{
    process          = $proc.ProcessName
    pid              = $id
    measured_at      = $tStart.ToString('o')
    duration_s       = [math]::Round($elapsed, 1)
    max_private_ws_mb = $peakPws
    max_private_mb   = $peakPriv
    cpu_percent      = $cpuPct
    max_threads      = $peakThreads
    handles_first    = $handlesFirst
    handles_last     = $handlesLast
    tcp_established  = $established.Count
    udp_endpoints    = $udp.Count
    violations       = @($violations)
    samples          = $samples
}
if ($JsonOut) {
    $result | ConvertTo-Json -Depth 4 | Out-File -FilePath $JsonOut -Encoding utf8
    Write-Host "JSON written to $JsonOut"
}

if ($violations.Count -gt 0) {
    Write-Host ''
    Write-Host 'OVER BUDGET:' -ForegroundColor Red
    $violations | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}
Write-Host ''
Write-Host 'Within budget.' -ForegroundColor Green
exit 0

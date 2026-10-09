# Windows agent resource budget

The user's explicit requirement: when idle in the background, `warpshot-agent.exe` must
use as few resources as possible — RAM especially, and the network almost not at
all. This budget is an **acceptance gate**. A change that breaks it does not merge.

## 1. Budget

"Idle" means the agent has been running for at least 10 minutes since the last
transfer or UI interaction, the network is connected, and `warpshot-ui.exe` is closed.

| Metric | Budget | How it is measured |
|---|---|---|
| Private working set (Task Manager "Memory" column) | **< 5 MB** | WMI `Win32_PerfFormattedData_PerfProc_Process.WorkingSetPrivate` (locale-independent) |
| Private bytes (commit) | < 12 MB | `Process.PrivateMemorySize64` |
| CPU | ≈ 0 (< 0.05 % average over 10 min) | `Process.TotalProcessorTime` delta |
| Threads | ≤ 6 (our 2 + OS-created pool/loader threads) | `Process.Threads.Count` |
| Handles | stable (no growth across samples) | `Process.HandleCount` |
| Network | **< 0.5 MB/day** (projected from 10 min) | the agent's own socket byte counters (debug IPC), cross-checked with `pktmon` |
| Timers while idle | 1 (the WebSocket keepalive, period K ≥ 60 s) | code review + ETW (optional) |

Expected network at idle: one TLS WebSocket to Cloudflare with an app-level ping
every 60–90 s, about 200 bytes per round trip including TCP/IP overhead, which
comes to ≈ 0.2–0.3 MB/day. Spike C fixes K.

## 2. Design rules for `warpshot-agent.exe`

1. **Two threads.** The Win32 message loop, plus one tokio `current_thread`
   runtime that holds the server WebSocket and the named-pipe listener. Nothing
   else runs at idle.
2. **Event-driven only.** No polling. The single idle timer is the WebSocket keepalive.
3. **P2P on demand.** The iroh endpoint and transfer tasks start when needed and
   stop after 30 s without work. Any extra runtime threads end with them.
4. **No WebView or Tauri in the agent.** The settings UI is a separate process that exits when closed.
5. **Lazy OS subsystems.** WinRT/COM objects for toasts, image codecs and the
   clipboard are created on use and released afterwards. Do not keep a
   `ToastNotifier` alive.
6. **Bounded buffers.** Files are streamed (64 KiB chunks); whole-file buffers
   are never used. Clipboard images are the only full in-memory payload, and they
   are dropped right after sending. Large `Vec`s are released (not just cleared)
   after a transfer.
7. **Trim after work.** After endpoint teardown, call
   `SetProcessWorkingSetSize(GetCurrentProcess(), usize::MAX, usize::MAX)` to
   release pages back to the OS.
8. **Power:** EcoQoS (`SetProcessInformation(ProcessPowerThrottling)`) while idle;
   normal QoS during a transfer so it stays fast.
9. **Storage on demand.** SQLite is opened when needed, with a small `cache_size`,
   and closed when idle. The log file is opened in append mode per write; there
   is no flush timer.
10. **Release profile.** `opt-level = "s"`, `lto = "fat"`, `codegen-units = 1`,
    `panic = "abort"`, `strip = true`. A smaller image means fewer touched pages.
11. **Dependency review.** Reject crates that start background threads or timers
    at init (some loggers, file watchers, metrics). Check this for every new dependency.

## 3. Measuring

```powershell
# After the agent has been idle ≥ 1 min; samples every 5 s for 10 min
powershell -ExecutionPolicy Bypass -File scripts\measure-idle.ps1 -ProcessName warpshot-agent
# Exit code 1 if over budget (used as a CI gate on the Windows runner)
```

Network cross-check with `pktmon` (requires admin):

```powershell
$rip = (Get-NetTCPConnection -OwningProcess (Get-Process warpshot-agent).Id -State Established).RemoteAddress
pktmon filter remove; pktmon filter add PT -i $rip
pktmon start --capture --pkt-size 0 --file-name idle.etl   # wait 10 min
pktmon stop; pktmon etl2txt idle.etl -o idle.txt         # sum the packet lengths
```

## 4. Results

| Date | Commit | Build | Private WS | Commit | Threads | CPU % | Net (proj./day) | Notes |
|---|---|---|---|---|---|---|---|---|
| – | – | – | – | – | – | – | – | Spike B will fill the first row |

//! Spike A probe (throwaway): times iroh 1.x bind, dial, path upgrade and bulk
//! transfer, and samples memory/threads of this process. Prints JSON lines.
//!
//!   iroh-probe listen [--relay default|eu|none] [--addr-file F] [--once]
//!   iroh-probe dial   [--relay default|eu|none] [--addr-file F] [--bytes N] [--mode any|direct|relay]

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use iroh::{
    Endpoint, EndpointAddr, RelayMode, TransportAddr,
    endpoint::{PathEvent, presets},
};
use n0_future::StreamExt;
use serde_json::{Value, json};

const ALPN: &[u8] = b"warpshot/spike-a/0";
const EKM_LABEL: &[u8] = b"EXPORTER-warpshot-spike-a";
const CHUNK: usize = 1 << 20;

#[derive(Clone, Copy, PartialEq)]
enum Relay {
    Default,
    Eu,
    None,
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Any,
    Direct,
    Relay,
}

struct Opts {
    relay: Relay,
    mode: Mode,
    addr_file: PathBuf,
    bytes: u64,
    once: bool,
}

fn parse(args: &[String]) -> Result<Opts> {
    let mut o = Opts {
        relay: Relay::Eu,
        mode: Mode::Any,
        addr_file: std::env::temp_dir().join("iroh-probe-addr.json"),
        bytes: 200 << 20,
        once: false,
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().ok_or_else(|| anyhow!("{a} needs a value"));
        match a.as_str() {
            "--relay" => {
                o.relay = match val()?.as_str() {
                    "default" => Relay::Default,
                    "eu" => Relay::Eu,
                    "none" => Relay::None,
                    v => bail!("bad --relay {v}"),
                }
            }
            "--mode" => {
                o.mode = match val()?.as_str() {
                    "any" => Mode::Any,
                    "direct" => Mode::Direct,
                    "relay" => Mode::Relay,
                    v => bail!("bad --mode {v}"),
                }
            }
            "--addr-file" => o.addr_file = val()?.into(),
            "--bytes" => o.bytes = val()?.parse()?,
            "--once" => o.once = true,
            _ => bail!("unknown argument {a}"),
        }
    }
    Ok(o)
}

fn ms(t: Instant) -> f64 {
    (t.elapsed().as_secs_f64() * 1e5).round() / 100.0
}

fn emit(v: Value) {
    println!("{v}");
}

async fn bind(o: &Opts, relay_only: bool) -> Result<(Endpoint, Value)> {
    let t0 = Instant::now();
    let relay_mode = match o.relay {
        Relay::Default => RelayMode::Default,
        // A6: a single-region relay map.
        Relay::Eu => RelayMode::custom([iroh::defaults::prod::default_eu_relay().url]),
        Relay::None => RelayMode::Disabled,
    };
    let mut b = Endpoint::builder(presets::Minimal)
        .relay_mode(relay_mode)
        // A6: no address lookup (no DNS/pkarr publishing, no mDNS).
        .clear_address_lookup()
        .alpns(vec![ALPN.to_vec()]);
    if relay_only {
        b = b.clear_ip_transports();
    }
    let ep = b.bind().await?;
    let bind_ms = ms(t0);
    let mut online_ms = Value::Null;
    if o.relay != Relay::None && std::env::var_os("PROBE_NO_WAIT_ONLINE").is_none() {
        tokio::time::timeout(Duration::from_secs(15), ep.online())
            .await
            .context("home relay not connected within 15 s")?;
        online_ms = json!(ms(t0));
    }
    Ok((ep, json!({ "bind_ms": bind_ms, "online_ms": online_ms })))
}

async fn listen(o: Opts) -> Result<()> {
    let m0 = mem();
    let (ep, t) = bind(&o, false).await?;
    let addr = ep.addr();
    std::fs::write(&o.addr_file, serde_json::to_string(&addr)?)?;
    emit(json!({
        "ev": "listening", "timing": t, "mem_before": m0, "mem_bound": mem(),
        "direct_addrs": addr.ip_addrs().count(), "threads_bound": thread_names(),
        "relay": addr.relay_urls().next().map(|u| u.to_string()),
    }));
    while let Some(incoming) = ep.accept().await {
        let conn = match incoming.accept() {
            Ok(acc) => acc.await?,
            Err(e) => {
                emit(json!({ "ev": "incoming-error", "err": e.to_string() }));
                continue;
            }
        };
        let (mut send, mut recv) = conn.accept_bi().await?;
        let mut hdr = [0u8; 8];
        recv.read_exact(&mut hdr).await?;
        let want = u64::from_be_bytes(hdr);
        let mut buf = vec![0u8; CHUNK];
        let mut got = 0u64;
        while let Some(n) = recv.read(&mut buf).await? {
            got += n as u64;
        }
        let mut ekm = [0u8; 32];
        conn.export_keying_material(&mut ekm, EKM_LABEL, b"")
            .map_err(|e| anyhow!("ekm: {e:?}"))?;
        send.write_all(&got.to_be_bytes()).await?;
        send.write_all(&ekm).await?;
        send.finish()?;
        let peak = mem();
        let _ = tokio::time::timeout(Duration::from_secs(10), conn.closed()).await;
        emit(json!({ "ev": "served", "want": want, "got": got, "mem_after_transfer": peak }));
        if o.once {
            break;
        }
    }
    ep.close().await;
    Ok(())
}

async fn dial(o: Opts) -> Result<()> {
    let m0 = mem();
    let threads_before = thread_names();
    let full: EndpointAddr = serde_json::from_str(&std::fs::read_to_string(&o.addr_file)?)?;
    let addr = match o.mode {
        Mode::Any => full.clone(),
        Mode::Direct => EndpointAddr::from_parts(full.id, full.ip_addrs().map(|a| TransportAddr::Ip(*a))),
        Mode::Relay => EndpointAddr::from_parts(
            full.id,
            full.relay_urls().map(|u| TransportAddr::Relay(u.clone())),
        ),
    };
    let (ep, t) = bind(&o, o.mode == Mode::Relay).await?;
    let m_bound = mem();

    let t1 = Instant::now();
    let conn = ep.connect(addr, ALPN).await?;
    let bind_to_connected_ms = t["bind_ms"].as_f64().unwrap_or(0.0) + ms(t1);
    let connect_ms = ms(t1);
    let paths_at_connect = paths_json(&conn);

    // A3: when does the first direct (IP) path get selected?
    let mut events = conn.path_events();
    let ev_task = tokio::spawn(async move {
        let mut first_direct = None;
        let mut log = Vec::new();
        while let Some(e) = events.next().await {
            let at = ms(t1);
            match &e {
                PathEvent::Opened { remote_addr, .. } => {
                    log.push(json!({ "at": at, "opened_ip": remote_addr.is_ip() }))
                }
                PathEvent::Closed { remote_addr, .. } => {
                    log.push(json!({ "at": at, "closed_ip": remote_addr.is_ip() }))
                }
                PathEvent::Selected { remote_addr, .. } => {
                    log.push(json!({ "at": at, "selected_ip": remote_addr.is_ip() }));
                    if remote_addr.is_ip() && first_direct.is_none() {
                        first_direct = Some(at);
                    }
                }
                _ => log.push(json!({ "at": at, "other": format!("{e:?}") })),
            }
        }
        (first_direct, log)
    });

    let (mut send, mut recv) = conn.open_bi().await?;
    let t2 = Instant::now();
    send.write_all(&o.bytes.to_be_bytes()).await?;
    let chunk = vec![0xA5u8; CHUNK];
    let mut left = o.bytes;
    let mut mem_peak = mem();
    while left > 0 {
        let n = left.min(CHUNK as u64) as usize;
        send.write_all(&chunk[..n]).await?;
        left -= n as u64;
        if (o.bytes - left) % (16 * CHUNK as u64) == 0 {
            let m = mem();
            if m["pws_kb"].as_u64() > mem_peak["pws_kb"].as_u64() {
                mem_peak = m;
            }
        }
    }
    send.finish()?;
    let mut resp = [0u8; 40];
    recv.read_exact(&mut resp).await?;
    let xfer_s = t2.elapsed().as_secs_f64();
    let mut got = [0u8; 8];
    got.copy_from_slice(&resp[..8]);
    let got = u64::from_be_bytes(got);
    let mut ekm = [0u8; 32];
    conn.export_keying_material(&mut ekm, EKM_LABEL, b"")
        .map_err(|e| anyhow!("ekm: {e:?}"))?;
    // Throwaway spike comparing a test-only export, not a secret in use.
    let ekm_equal = ekm[..] == resp[8..];
    let paths_after = paths_json(&conn);
    let stats = format!("{:?}", conn.stats());

    conn.close(0u32.into(), b"done");
    let m_open = mem();
    ep.close().await;
    let (first_direct_ms, path_log) = ev_task.await?;
    let m_closed = mem();
    // Sample threads every 10 s while the process stays idle after close.
    let linger: u64 = std::env::var("PROBE_LINGER_S").ok().and_then(|v| v.parse().ok()).unwrap_or(30);
    let mut thread_timeline = Vec::new();
    for s in (10..=linger).step_by(10) {
        tokio::time::sleep(Duration::from_secs(10)).await;
        thread_timeline.push(json!({ "s": s, "threads": thread_count() }));
    }
    let m_30s = mem();
    let threads_30s = thread_names();
    trim_working_set();
    let m_trimmed = mem();

    emit(json!({
        "ev": "dial-result",
        "mode": match o.mode { Mode::Any => "any", Mode::Direct => "direct", Mode::Relay => "relay" },
        "timing": t,
        "connect_ms": connect_ms, "bind_to_connected_ms": bind_to_connected_ms,
        "first_direct_ms": first_direct_ms,
        "paths_at_connect": paths_at_connect,
        "paths_after_transfer": paths_after,
        "path_events": path_log,
        "bytes": o.bytes, "got": got,
        "mb_per_s": ((o.bytes as f64 / 1048576.0) / xfer_s * 10.0).round() / 10.0,
        "ekm_equal": ekm_equal,
        "mem": {
            "before_bind": m0, "bound": m_bound, "peak_transfer": mem_peak,
            "conn_open_after_transfer": m_open, "after_close": m_closed,
            "close_plus_30s": m_30s, "after_trim": m_trimmed,
        },
        "stats": stats,
        "threads_before_bind": threads_before, "threads_close_plus_30s": threads_30s, "thread_timeline": thread_timeline,
    }));
    Ok(())
}

fn paths_json(conn: &iroh::endpoint::Connection) -> Value {
    let paths = conn.paths();
    Value::Array(
        paths
            .iter()
            .map(|p| json!({ "ip": p.is_ip(), "relay": p.is_relay(), "selected": p.is_selected() }))
            .collect(),
    )
}

#[cfg(windows)]
fn mem() -> Value {
    use windows_sys::Win32::System::{
        ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX2},
        Threading::GetCurrentProcess,
    };
    // SAFETY: plain Win32 query into a correctly sized, zeroed struct.
    let c = unsafe {
        let mut c: PROCESS_MEMORY_COUNTERS_EX2 = std::mem::zeroed();
        c.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX2>() as u32;
        GetProcessMemoryInfo(
            GetCurrentProcess(),
            (&mut c as *mut PROCESS_MEMORY_COUNTERS_EX2).cast::<PROCESS_MEMORY_COUNTERS>(),
            c.cb,
        );
        c
    };
    json!({
        "pws_kb": c.PrivateWorkingSetSize / 1024,
        "priv_kb": c.PrivateUsage / 1024,
        "ws_kb": c.WorkingSetSize / 1024,
        "threads": thread_count(),
    })
}

#[cfg(windows)]
fn thread_count() -> u32 {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
        System::{
            Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next},
            Threading::GetCurrentProcessId,
        },
    };
    // SAFETY: Toolhelp snapshot iteration with a correctly sized entry; the handle is closed.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snap == INVALID_HANDLE_VALUE {
            return 0;
        }
        let pid = GetCurrentProcessId();
        let mut e: THREADENTRY32 = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        let mut n = 0;
        if Thread32First(snap, &mut e) != 0 {
            loop {
                if e.th32OwnerProcessID == pid {
                    n += 1;
                }
                if Thread32Next(snap, &mut e) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
        n
    }
}

/// Thread descriptions of this process ("" for unnamed OS pool threads).
#[cfg(windows)]
fn thread_names() -> Value {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, INVALID_HANDLE_VALUE, LocalFree},
        System::{
            Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next},
            Threading::{GetCurrentProcessId, GetThreadDescription, OpenThread, THREAD_QUERY_LIMITED_INFORMATION},
        },
    };
    let mut names = Vec::new();
    // SAFETY: Toolhelp iteration; each opened thread handle and description buffer is freed.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snap == INVALID_HANDLE_VALUE {
            return Value::Null;
        }
        let pid = GetCurrentProcessId();
        let mut e: THREADENTRY32 = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        let mut ok = Thread32First(snap, &mut e) != 0;
        while ok {
            if e.th32OwnerProcessID == pid {
                let h = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, 0, e.th32ThreadID);
                let mut name = String::from("?");
                if !h.is_null() {
                    let mut p: *mut u16 = std::ptr::null_mut();
                    if GetThreadDescription(h, &mut p) >= 0 && !p.is_null() {
                        let mut len = 0;
                        while *p.add(len) != 0 {
                            len += 1;
                        }
                        name = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
                        LocalFree(p.cast());
                    }
                    CloseHandle(h);
                }
                names.push(Value::String(name));
            }
            ok = Thread32Next(snap, &mut e) != 0;
        }
        CloseHandle(snap);
    }
    Value::Array(names)
}

#[cfg(not(windows))]
fn thread_names() -> Value {
    Value::Null
}

#[cfg(windows)]
fn trim_working_set() {
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, SetProcessWorkingSetSize};
    // SAFETY: (-1, -1) asks Windows to trim this process's working set.
    unsafe {
        SetProcessWorkingSetSize(GetCurrentProcess(), usize::MAX, usize::MAX);
    }
}

#[cfg(not(windows))]
fn mem() -> Value {
    Value::Null
}

#[cfg(not(windows))]
fn trim_working_set() {}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((cmd, rest)) = args.split_first() else {
        bail!("usage: iroh-probe listen|dial [options]");
    };
    let o = parse(rest)?;
    match cmd.as_str() {
        "listen" => listen(o).await,
        "dial" => dial(o).await,
        c => bail!("unknown command {c}"),
    }
}

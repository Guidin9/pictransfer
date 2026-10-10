//! `warpctl` — headless Warpshot peer for end-to-end tests and spikes.
//!
//! Until the server client lands, peers find each other through an address file
//! written by `listen` (instead of a wake envelope). Keys are stored with an
//! INSECURE test keystore: this tool is for tests, never for real devices.

// Test tool, not library code: small index arithmetic on its own files is fine.
#![allow(clippy::arithmetic_side_effects)]

use std::path::{Path, PathBuf};

use warpshot_core::{
    keys::{EndpointId, KeyError, Keystore, short_hex},
    log::{Log, Op, RecordBody, RemoveReason, platform, sign_record},
    net::{
        self, NetError, Relay,
        store::{Device, now_ms, write_atomic},
        xfer::{self as nx, Policy},
    },
    pair::{QrPayload, Window},
    wake::DialInfo,
};
use zeroize::Zeroizing;

/// Plaintext "keystore" for test peers only.
struct InsecureTestKeystore;

impl Keystore for InsecureTestKeystore {
    fn wrap(&self, _label: &str, plain: &[u8]) -> Result<Vec<u8>, KeyError> {
        Ok(plain.to_vec())
    }
    fn unwrap(&self, _label: &str, wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        Ok(Zeroizing::new(wrapped.to_vec()))
    }
}

struct Args {
    cmd: String,
    pos: Vec<String>,
    dir: PathBuf,
    name: String,
    platform: u64,
    relay: Relay,
    addr_file: Option<PathBuf>,
    out: Option<PathBuf>,
    text: Option<String>,
    yes: bool,
    accept_large: bool,
    once: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().ok_or_else(usage)?;
    let mut a = Args {
        cmd,
        pos: vec![],
        dir: PathBuf::from(".warpctl"),
        name: "warpctl".into(),
        platform: platform::WINDOWS,
        relay: Relay::Eu,
        addr_file: None,
        out: None,
        text: None,
        yes: false,
        accept_large: false,
        once: false,
    };
    while let Some(arg) = it.next() {
        let mut val = || it.next().ok_or_else(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "--dir" => a.dir = val()?.into(),
            "--name" => a.name = val()?,
            "--platform" => {
                a.platform = match val()?.as_str() {
                    "windows" => platform::WINDOWS,
                    "android" => platform::ANDROID,
                    p => return Err(format!("unknown platform {p}")),
                }
            }
            "--no-relay" => a.relay = Relay::Disabled,
            "--addr-file" => a.addr_file = Some(val()?.into()),
            "--out" => a.out = Some(val()?.into()),
            "--text" => a.text = Some(val()?),
            "--yes" => a.yes = true,
            "--accept-large" => a.accept_large = true,
            "--once" => a.once = true,
            s if s.starts_with("--") => return Err(format!("unknown option {s}")),
            _ => a.pos.push(arg),
        }
    }
    Ok(a)
}

fn usage() -> String {
    "usage: warpctl <init|pair-display|pair-scan QR|listen|send DEVICE [PATH]|devices|log|remove DEVICE> \
     [--dir D] [--name N] [--platform windows|android] [--no-relay] [--addr-file F] [--out DIR] [--text T] [--yes] [--once]"
        .into()
}

fn emit(v: String) {
    println!("{v}");
}

fn json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn load(dir: &Path) -> Result<Device, String> {
    Device::load(dir, &InsecureTestKeystore, now_ms()).map_err(|e| format!("load: {e}"))
}

fn save(dev: &Device, dir: &Path) -> Result<(), String> {
    dev.save(dir, &InsecureTestKeystore)
        .map_err(|e| format!("save: {e}"))
}

/// Resolves a device by exact name or id-hex prefix (≥ 8 chars).
fn find_device(log: &Log, q: &str) -> Result<EndpointId, String> {
    let hits: Vec<EndpointId> = log
        .members()
        .iter()
        .filter(|(id, d)| {
            d.name == q || (q.len() >= 8 && hex(&id.0).starts_with(&q.to_ascii_lowercase()))
        })
        .map(|(id, _)| *id)
        .collect();
    match hits.as_slice() {
        [one] => Ok(*one),
        [] => Err(format!("no device {q}")),
        _ => Err(format!("ambiguous device {q}")),
    }
}

fn write_addr(path: &Path, id: &EndpointId, d: &DialInfo) -> Result<(), String> {
    let addrs: Vec<String> = d.addrs.iter().map(|a| json_str(&a.to_string())).collect();
    let relay = d
        .relay
        .as_deref()
        .map(json_str)
        .unwrap_or_else(|| "null".into());
    let body = format!(
        "{{\"id\":\"{}\",\"relay\":{relay},\"addrs\":[{}]}}\n",
        hex(&id.0),
        addrs.join(",")
    );
    write_atomic(path, body.as_bytes()).map_err(|e| e.to_string())
}

fn read_addr(path: &Path) -> Result<(EndpointId, DialInfo), String> {
    // Minimal parser for the file written by write_addr.
    let s = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let field = |k: &str| -> Option<&str> {
        let i = s.find(&format!("\"{k}\":"))? + k.len() + 3;
        s.get(i..)
    };
    let id_hex = field("id")
        .and_then(|r| r.strip_prefix('"'))
        .and_then(|r| r.get(..64))
        .ok_or("bad addr file")?;
    let mut id = [0u8; 32];
    for (i, b) in id.iter_mut().enumerate() {
        *b = u8::from_str_radix(id_hex.get(i * 2..i * 2 + 2).ok_or("bad id")?, 16)
            .map_err(|_| "bad id")?;
    }
    let relay = field("relay")
        .and_then(|r| r.strip_prefix('"'))
        .and_then(|r| r.split('"').next())
        .map(str::to_owned);
    let addrs = field("addrs")
        .and_then(|r| r.strip_prefix('['))
        .and_then(|r| r.split(']').next())
        .map(|list| {
            list.split(',')
                .filter_map(|a| a.trim().trim_matches('"').parse().ok())
                .collect()
        })
        .unwrap_or_default();
    Ok((EndpointId(id), DialInfo { relay, addrs }))
}

async fn accept_alpn(
    ep: &iroh::Endpoint,
    alpn: &[u8],
) -> Result<iroh::endpoint::Connection, String> {
    loop {
        let inc = ep.accept().await.ok_or("endpoint closed")?;
        let Ok(acc) = inc.accept() else { continue };
        let Ok(conn) = acc.await else { continue };
        if conn.alpn() == alpn {
            return Ok(conn);
        }
        net::close(&conn, warpshot_core::xfer::code::PROTOCOL);
    }
}

/// Emits path changes (direct vs relay, no addresses) with ms since `t0`.
fn trace_paths(conn: &iroh::endpoint::Connection, t0: std::time::Instant) {
    let c = conn.clone();
    tokio::spawn(async move {
        net::watch_paths(&c, |n| {
            emit(format!(
                "{{\"ev\":\"path\",\"t_ms\":{},\"note\":{}}}",
                t0.elapsed().as_millis(),
                json_str(&format!("{n:?}"))
            ))
        })
        .await;
    });
}

async fn run(a: Args) -> Result<(), String> {
    match a.cmd.as_str() {
        "init" => {
            if a.dir.join("device.cbor").exists() {
                return Err("already initialized".into());
            }
            let dev = Device::new(&a.name, a.platform).map_err(|e| e.to_string())?;
            save(&dev, &a.dir)?;
            emit(format!(
                "{{\"ev\":\"init\",\"id\":\"{}\",\"name\":{}}}",
                hex(&dev.id().0),
                json_str(&dev.name)
            ));
        }
        "pair-display" => {
            let mut dev = load(&a.dir)?;
            let ep = net::bind(&dev.keys.ik, a.relay)
                .await
                .map_err(|e| e.to_string())?;
            let mut window = Window::open(
                dev.id(),
                net::dial_info(&ep),
                dev.name.clone(),
                dev.group_id(),
                now_ms() / 1000,
            )
            .map_err(|e| e.to_string())?;
            emit(format!(
                "{{\"ev\":\"qr\",\"text\":{}}}",
                json_str(&window.qr_text())
            ));
            if let Some(f) = &a.addr_file {
                write_atomic(f, window.qr_text().as_bytes()).map_err(|e| e.to_string())?;
            }
            let conn = accept_alpn(&ep, warpshot_core::pair::ALPN).await?;
            let yes = a.yes;
            let paired = net::pair::display(
                &ep,
                conn,
                &mut window,
                &dev,
                now_ms(),
                |s| async move {
                    emit(format!(
                        "{{\"ev\":\"sas\",\"sas\":\"{}\",\"peer\":{}}}",
                        s.sas,
                        json_str(&s.device.name)
                    ));
                    yes
                },
                |_recs| async { Ok::<(), NetError>(()) },
            )
            .await
            .map_err(|e| format!("pair: {e}"))?;
            dev.log = Some(paired.log);
            save(&dev, &a.dir)?;
            emit(format!(
                "{{\"ev\":\"paired\",\"peer\":\"{}\"}}",
                hex(&paired.peer.0)
            ));
            ep.close().await;
        }
        "pair-scan" => {
            let mut dev = load(&a.dir)?;
            let text = match (a.pos.first(), &a.addr_file) {
                (Some(t), _) => t.clone(),
                (None, Some(f)) => std::fs::read_to_string(f).map_err(|e| e.to_string())?,
                _ => return Err("pair-scan needs the QR text or --addr-file".into()),
            };
            let qr = QrPayload::parse(text.trim()).map_err(|e| format!("qr: {e}"))?;
            let ep = net::bind(&dev.keys.ik, a.relay)
                .await
                .map_err(|e| e.to_string())?;
            let yes = a.yes;
            let paired = net::pair::scan(
                &ep,
                &qr,
                &dev,
                now_ms(),
                |s| async move {
                    emit(format!(
                        "{{\"ev\":\"sas\",\"sas\":\"{}\",\"peer\":{}}}",
                        s.sas,
                        json_str(&s.device.name)
                    ));
                    yes
                },
                |_recs| async { Ok::<(), NetError>(()) },
            )
            .await
            .map_err(|e| format!("pair: {e}"))?;
            dev.log = Some(paired.log);
            save(&dev, &a.dir)?;
            emit(format!(
                "{{\"ev\":\"paired\",\"peer\":\"{}\"}}",
                hex(&paired.peer.0)
            ));
            ep.close().await;
        }
        "listen" => {
            let mut dev = load(&a.dir)?;
            let out = a.out.clone().unwrap_or_else(|| a.dir.join("received"));
            std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
            let ep = net::bind(&dev.keys.ik, a.relay)
                .await
                .map_err(|e| e.to_string())?;
            if let Some(f) = &a.addr_file {
                // Give QUIC address discovery and the port mapper a moment.
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                write_addr(f, &dev.id(), &net::dial_info(&ep))?;
            }
            emit(format!(
                "{{\"ev\":\"listening\",\"id\":\"{}\"}}",
                hex(&dev.id().0)
            ));
            loop {
                let conn = accept_alpn(&ep, warpshot_core::xfer::ALPN).await?;
                let t0 = std::time::Instant::now();
                trace_paths(&conn, t0);
                let mut log = dev.log.clone().ok_or("not paired")?;
                let res = async {
                    let mut s = nx::accept(&ep, conn.clone(), &log).await?;
                    if s.sync_logs(&mut log, now_ms()).await? {
                        dev.log = Some(log.clone());
                        save(&dev, &a.dir).map_err(|_| NetError::State("save"))?;
                    }
                    s.receive(
                        &Policy {
                            dir: out.clone(),
                            max_size: 500 << 20,
                            accept_large: a.accept_large,
                        },
                        |_| true,
                    )
                    .await
                }
                .await;
                match res {
                    Ok(items) => {
                        emit(format!(
                            "{{\"ev\":\"done\",\"ms\":{},\"direct\":{}}}",
                            t0.elapsed().as_millis(),
                            net::is_direct(&conn)
                        ));
                        for r in items {
                            let path = r
                                .path
                                .as_ref()
                                .map(|p| json_str(&p.display().to_string()))
                                .unwrap_or_else(|| "null".into());
                            let text = r
                                .item
                                .text
                                .as_deref()
                                .map(json_str)
                                .unwrap_or_else(|| "null".into());
                            emit(format!(
                                "{{\"ev\":\"received\",\"id\":{},\"size\":{},\"path\":{path},\"text\":{text}}}",
                                r.item.id, r.item.size
                            ));
                        }
                    }
                    Err(e) => emit(format!(
                        "{{\"ev\":\"error\",\"err\":{}}}",
                        json_str(&e.to_string())
                    )),
                }
                if a.once {
                    break;
                }
            }
            ep.close().await;
        }
        "send" => {
            let mut dev = load(&a.dir)?;
            let mut log = dev.log.clone().ok_or("not paired")?;
            let target = find_device(&log, a.pos.first().ok_or("send needs a device")?)?;
            let (aid, dial) = read_addr(
                a.addr_file
                    .as_deref()
                    .ok_or("send needs --addr-file (until the server client lands)")?,
            )?;
            if aid != target {
                return Err("address file is for another device".into());
            }
            let mut items = Vec::new();
            if let Some(t) = &a.text {
                items.push(nx::text_item(1, t, now_ms()).map_err(|e| e.to_string())?);
            }
            for (i, p) in a.pos.iter().skip(1).enumerate() {
                items.push(
                    nx::file_item(i as u32 + 2, Path::new(p), now_ms())
                        .map_err(|e| e.to_string())?,
                );
            }
            if items.is_empty() {
                return Err("nothing to send".into());
            }
            let ep = net::bind(&dev.keys.ik, a.relay)
                .await
                .map_err(|e| e.to_string())?;
            let t0 = std::time::Instant::now();
            let mut s = nx::dial(&ep, &log, &target, &dial, [0; 16])
                .await
                .map_err(|e| format!("dial: {e}"))?;
            let connect_ms = t0.elapsed().as_millis();
            trace_paths(&s.conn, t0);
            if s.sync_logs(&mut log, now_ms())
                .await
                .map_err(|e| e.to_string())?
            {
                dev.log = Some(log);
                save(&dev, &a.dir)?;
            }
            let results = s
                .send_items(items)
                .await
                .map_err(|e| format!("send: {e}"))?;
            let ok = results.iter().all(|(_, ok)| *ok);
            emit(format!(
                "{{\"ev\":\"sent\",\"ok\":{ok},\"connect_ms\":{connect_ms},\"total_ms\":{}}}",
                t0.elapsed().as_millis()
            ));
            ep.close().await;
            if !ok {
                return Err("some items failed".into());
            }
        }
        "devices" => {
            let dev = load(&a.dir)?;
            let log = dev.log.as_ref().ok_or("not paired")?;
            for (id, d) in log.members() {
                emit(format!(
                    "{{\"id\":\"{}\",\"name\":{},\"platform\":{},\"me\":{}}}",
                    hex(&id.0),
                    json_str(&d.name),
                    d.platform,
                    *id == dev.id()
                ));
            }
        }
        "log" => {
            let dev = load(&a.dir)?;
            let log = dev.log.as_ref().ok_or("not paired")?;
            for r in log.records() {
                let op = match &r.body.op {
                    Op::Genesis(_) => "genesis",
                    Op::Add(_) => "add",
                    Op::Remove(_) => "remove",
                    Op::Update(_) => "update",
                };
                emit(format!(
                    "{{\"seq\":{},\"op\":\"{op}\",\"subject\":\"{}\",\"signer\":\"{}\",\"id\":\"{}\"}}",
                    r.body.seq,
                    short_hex(&r.body.subject.0),
                    short_hex(&r.signer.0),
                    short_hex(&r.id.0)
                ));
            }
        }
        "remove" => {
            let mut dev = load(&a.dir)?;
            let mut log = dev.log.clone().ok_or("not paired")?;
            let target = find_device(&log, a.pos.first().ok_or("remove needs a device")?)?;
            let (seq, prev) = log.next_position();
            let body = RecordBody {
                group_id: log.group_id(),
                seq,
                prev,
                created_at: now_ms(),
                subject: target,
                op: Op::Remove(RemoveReason::User),
            };
            log.append(&sign_record(&dev.keys.ik, &body), now_ms())
                .map_err(|e| e.to_string())?;
            dev.log = Some(log);
            save(&dev, &a.dir)?;
            emit("{\"ev\":\"removed\"}".into());
        }
        _ => return Err(usage()),
    }
    Ok(())
}

fn main() {
    let result = parse_args().and_then(|a| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        rt.block_on(run(a))
    });
    if let Err(e) = result {
        eprintln!("warpctl: {e}");
        std::process::exit(1);
    }
}

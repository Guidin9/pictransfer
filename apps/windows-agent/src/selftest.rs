//! `warpshot-agent --selftest`: exercises the non-interactive modules and
//! returns a JSON report. It never writes the clipboard, never shows a toast,
//! never changes autostart and reports only kinds, sizes, flags and timings.

// Arithmetic here is on small fixed constants (a 1080p test image).
#![allow(clippy::arithmetic_side_effects)]

use std::{sync::Arc, time::Instant};

use serde_json::{Value, json};

use crate::{
    autostart, clipboard,
    hotkey::{self, Hotkey},
    image, pipe, power, single_instance, toast, win,
};

fn ms(t: Instant) -> f64 {
    (t.elapsed().as_secs_f64() * 1e4).round() / 10.0
}

fn err<E: std::fmt::Display>(e: E) -> Value {
    json!({ "error": e.to_string() })
}

struct Echo;

impl pipe::Handler for Echo {
    async fn call(&self, method: &str, params: Value) -> Result<Value, pipe::RpcError> {
        match method {
            "echo" => Ok(params),
            _ => Err(pipe::RpcError::method_not_found()),
        }
    }
}

fn hotkey_report() -> Value {
    let Ok(hk) = Hotkey::parse(hotkey::DEFAULT_HOTKEY) else {
        return err("default hotkey does not parse");
    };
    let q = Hotkey::parse("Ctrl+Alt+Q").ok();
    let trq = |h: &Hotkey| match hotkey::altgr_conflict_for_klid(h, "0000041F") {
        Ok(o) => json!(o.map(|o| o.to_string())),
        Err(e) => err(e),
    };
    json!({
        "default": hk.to_string(),
        "round_trip": Hotkey::parse(&hk.to_string()).ok() == Some(hk),
        "altgr_current_layout": hotkey::altgr_conflict_current(&hk).map(|o| o.to_string()),
        "altgr_installed_layouts": hotkey::altgr_conflicts_installed(&hk).len(),
        "installed_layouts": hotkey::installed_layouts().len(),
        "tr_q_ctrl_alt_q": q.as_ref().map(trq),
        "tr_q_default": trq(&hk),
    })
}

fn clipboard_report() -> Value {
    let kind = clipboard::available_kind();
    let t = Instant::now();
    // Read-only, with no owner window; content is dropped unseen.
    let read = clipboard::read(std::ptr::null_mut());
    let read_ms = ms(t);
    let read = match read {
        Ok(Some(c)) => json!(format!("{c:?}")), // kind and size only
        Ok(None) => json!(null),
        Err(e) => err(e),
    };
    json!({ "available": kind.map(clipboard::ClipKind::as_str), "read": read, "read_ms": read_ms })
}

fn image_report() -> Value {
    // Synthetic 1920×1080 bottom-up 32 bpp DIB with a gradient.
    let (w, h) = (1920u32, 1080u32);
    let mut dib = Vec::with_capacity(40 + (w * h * 4) as usize);
    for v in [40u32, w, h] {
        dib.extend_from_slice(&v.to_le_bytes());
    }
    dib.extend_from_slice(&1u16.to_le_bytes());
    dib.extend_from_slice(&32u16.to_le_bytes());
    dib.extend_from_slice(&[0u8; 24]);
    for y in 0..h {
        for x in 0..w {
            dib.extend_from_slice(&[(x % 256) as u8, (y % 256) as u8, 128, 0]);
        }
    }
    let t = Instant::now();
    let png = image::dib_to_png(&dib);
    let encode_ms = ms(t);
    let Ok(png) = png else {
        return err("dib_to_png failed");
    };
    let t = Instant::now();
    let back = image::png_to_dibv5(&png);
    let decode_ms = ms(t);
    json!({
        "dib_to_png_ms_1080p": encode_ms,
        "png_bytes": png.len(),
        "png_to_dibv5_ms": decode_ms,
        "dibv5_ok": back.map(|d| d.len() == 124 + (w * h * 4) as usize).unwrap_or(false),
    })
}

fn pipe_report() -> Value {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return err(e),
    };
    rt.block_on(async {
        let name = match win::current_user_sid() {
            Ok(sid) => format!(r"\\.\pipe\warpshot-selftest-{sid}-{}", std::process::id()),
            Err(e) => return err(e),
        };
        let server = match pipe::PipeServer::bind(&name) {
            Ok(s) => s,
            Err(e) => return err(e),
        };
        tokio::spawn(server.serve(Arc::new(Echo)));
        let t = Instant::now();
        let mut c = match pipe::PipeClient::connect(&name).await {
            Ok(c) => c,
            Err(e) => return err(e),
        };
        let connect_ms = ms(t);
        let t = Instant::now();
        let ok = c.call("echo", json!({"x": 1})).await.ok() == Some(json!({"x": 1}));
        json!({ "round_trip_ok": ok, "connect_ms": connect_ms, "call_ms": ms(t) })
    })
}

fn instance_report() -> Value {
    let name = format!("Local\\warpshot-agent-selftest-{}", std::process::id());
    let first = single_instance::acquire_named(&name);
    let second = single_instance::acquire_named(&name);
    let agent_running = match single_instance::acquire() {
        Ok(single_instance::Instance::AlreadyRunning) => json!(true),
        Ok(single_instance::Instance::First(_)) => json!(false),
        Err(e) => err(e),
    };
    json!({
        "first_acquired": matches!(first, Ok(single_instance::Instance::First(_))),
        "second_refused": matches!(second, Ok(single_instance::Instance::AlreadyRunning)),
        "agent_running": agent_running,
    })
}

/// Runs every check and returns the report.
pub fn run() -> Value {
    let started = Instant::now();
    let sid = win::current_user_sid();
    let toast_check = toast::validate(&toast::Toast {
        title: "Warpshot",
        body: "selftest",
        image: None,
        id: Some("selftest"),
    });
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "user_sid_ok": sid.as_ref().is_ok_and(|s| s.starts_with("S-1-5-")),
        "pipe_name_ok": pipe::pipe_name().is_ok(),
        "hotkey": hotkey_report(),
        "clipboard": clipboard_report(),
        "image": image_report(),
        "pipe": pipe_report(),
        "single_instance": instance_report(),
        "autostart_enabled": autostart::is_enabled().map_err(|e| e.to_string()).map_or_else(|e| json!({"error": e}), |b| json!(b)),
        "power": { "eco_qos_on": power::set_eco_qos(true), "eco_qos_off": power::set_eco_qos(false), "trim": power::trim_working_set() },
        "toast_xml_winrt_ok": toast_check.is_ok(),
        "total_ms": ms(started),
    })
}

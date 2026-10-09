//! The agent's network side, on the single tokio `current_thread` runtime:
//! device state, the server WebSocket (§6.3), wakes, transfers, pairing (§5),
//! membership changes, settings and history, plus the docs/ipc.md methods.
//!
//! Win32 work (clipboard writes, toasts, tray menu, hotkey registration) goes
//! back to the UI thread as [`UiMsg`]s. Nothing here logs content, names,
//! addresses or keys.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use serde_json::{Map, Value, json};
use tokio::sync::{Mutex, broadcast, oneshot};
use warpshot_core::{
    client::{Client, CreateToken, DevicePresence, Event, Via, WsConfig, WsHandle},
    history::{self, Direction, Retention},
    keys::{EndpointId, IdentityKey},
    log::{Head, Op, RecordBody, RemoveReason, platform, sign_record},
    net::{
        self, NetError, Relay,
        flow::{self, PendingSessions, WakeAction},
        manager::EndpointManager,
        pair::PeerSummary,
        store::{Device, now_ms, write_atomic},
        xfer::{self as nx, OutItem, Policy, Received, Source},
    },
    pair::{PairError, Window},
    wake::{ReplayCache, WakeError},
    xfer::{self as wx, Item},
};

use crate::{
    clipboard::ClipContent,
    dpapi::Dpapi,
    hotkey::{self, Hotkey},
    pipe::{self, RpcError},
    power,
    tray::{DeviceItem, MenuModel},
};

/// Work for the UI thread.
#[derive(Debug)]
pub enum UiMsg {
    Toast {
        title: String,
        body: String,
        image: Option<PathBuf>,
    },
    ClipText(String),
    /// A received image file to put on the clipboard (PNG, else as a file).
    ClipImage(PathBuf),
    ClipFiles(Vec<PathBuf>),
    Menu(MenuModel),
    /// Register this hotkey (canonical string) instead of the current one.
    Hotkey(String),
}

/// Requests from the UI thread.
#[derive(Debug)]
pub enum Cmd {
    SendClip(ClipContent),
    SetDefaultIndex(usize),
}

pub type UiSink = Box<dyn Fn(UiMsg) + Send + Sync>;

const MAX_RECEIVE_DEFAULT_MB: u64 = 500;
const WAKE_TTL: u32 = 60;

/// `%LOCALAPPDATA%\Warpshot`, or `WARPSHOT_DATA_DIR` (tests).
pub fn data_dir() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("WARPSHOT_DATA_DIR") {
        return Some(PathBuf::from(d));
    }
    std::env::var_os("LOCALAPPDATA").map(|p| PathBuf::from(p).join("Warpshot"))
}

fn platform_str(p: u64) -> &'static str {
    match p {
        platform::WINDOWS => "windows",
        platform::ANDROID => "android",
        _ => "other",
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn parse_id(s: &str) -> Option<EndpointId> {
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut id = [0u8; 32];
    for (i, out) in id.iter_mut().enumerate() {
        let pos = i.checked_mul(2)?;
        *out = u8::from_str_radix(s.get(pos..pos.checked_add(2)?)?, 16).ok()?;
    }
    Some(EndpointId(id))
}

fn lk<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn bad(msg: &str) -> RpcError {
    RpcError::new(pipe::code::INVALID_PARAMS, msg)
}

fn fail(code: &str) -> RpcError {
    RpcError::new(code, code)
}

fn net_code(e: &NetError) -> &'static str {
    match e {
        NetError::Timeout => "timeout",
        NetError::Fork => "fork",
        NetError::Rejected | NetError::Declined(_) => "rejected",
        NetError::Server(_) | NetError::HeadMoved => "server",
        NetError::Identity => "not-member",
        NetError::TooLarge => "too-large",
        _ => "network",
    }
}

fn default_settings() -> Value {
    let downloads = std::env::var_os("USERPROFILE")
        .map(|p| PathBuf::from(p).join("Downloads").join("Warpshot"))
        .unwrap_or_else(|| PathBuf::from("Warpshot"));
    json!({
        "hotkey": hotkey::DEFAULT_HOTKEY,
        "default_target": null,
        "save_dir": downloads.display().to_string(),
        "ask_above_mb": MAX_RECEIVE_DEFAULT_MB,
        "relay_data": true,
        "autostart": true,
        "on_receive": {"save": true, "clipboard": true, "notify": true, "history": true},
        "history_days": 30,
        "history_items": 200,
    })
}

/// Validates a partial settings object against the defaults' types.
fn merge_settings(cur: &mut Value, patch: &Map<String, Value>) -> Result<(), RpcError> {
    let defaults = default_settings();
    for (k, v) in patch {
        let Some(d) = defaults.get(k) else { continue };
        let ok = match (k.as_str(), v) {
            ("default_target", Value::Null) => true,
            ("default_target", Value::String(s)) => parse_id(s).is_some(),
            ("ask_above_mb" | "history_days" | "history_items", Value::Number(n)) => {
                n.as_u64().is_some_and(|n| (1..=100_000).contains(&n))
            }
            ("save_dir", Value::String(s)) => Path::new(s).is_absolute(),
            ("hotkey", Value::String(s)) => Hotkey::parse(s).is_ok(),
            ("on_receive", Value::Object(m)) => m.values().all(Value::is_boolean),
            (_, v) => std::mem::discriminant(v) == std::mem::discriminant(d),
        };
        if !ok {
            return Err(bad(k));
        }
        if let (Value::Object(cur_m), Value::Object(new_m)) = (&mut cur[k.as_str()], v)
            && k == "on_receive"
        {
            for (kk, vv) in new_m {
                cur_m.insert(kk.clone(), vv.clone());
            }
        } else if let Value::Object(m) = cur {
            m.insert(k.clone(), v.clone());
        }
    }
    Ok(())
}

/// Local time as `YYYY-MM-DD HHMMSS` for generated file names.
fn local_stamp() -> String {
    // SAFETY: GetLocalTime fills the struct we pass.
    let t = unsafe {
        let mut t = std::mem::zeroed::<windows_sys::Win32::Foundation::SYSTEMTIME>();
        windows_sys::Win32::System::SystemInformation::GetLocalTime(&mut t);
        t
    };
    format!(
        "{:04}-{:02}-{:02} {:02}{:02}{:02}",
        t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond
    )
}

/// Builds transfer items from clipboard content.
pub fn clip_items(c: ClipContent) -> Result<Vec<OutItem>, &'static str> {
    let now = now_ms();
    match c {
        ClipContent::Png(png) => Ok(vec![OutItem {
            item: Item {
                id: 1,
                kind: wx::kind::IMAGE,
                name: format!("Screenshot {}.png", local_stamp()),
                mime: "image/png".into(),
                size: png.len() as u64,
                created_at: now,
                text: None,
            },
            source: Source::Bytes(png),
        }]),
        ClipContent::Text(t) => Ok(vec![nx::text_item(1, &t, now).map_err(|_| "too-large")?]),
        ClipContent::Files(paths) => {
            let mut items = Vec::new();
            for p in paths.iter().filter(|p| p.is_file()) {
                let id = u32::try_from(items.len())
                    .map_err(|_| "too-large")?
                    .saturating_add(1);
                items.push(nx::file_item(id, p, now).map_err(|_| "io")?);
            }
            if items.is_empty() {
                Err("empty")
            } else {
                Ok(items)
            }
        }
    }
}

pub struct Service {
    dir: PathBuf,
    ks: Dpapi,
    dev: Mutex<Device>,
    client: Option<Client>,
    server_url: Option<String>,
    mgr: Arc<EndpointManager>,
    replay: Mutex<ReplayCache>,
    pending: Mutex<PendingSessions>,
    send_lock: Mutex<()>,
    ws: Mutex<Option<WsHandle>>,
    acks: Mutex<HashMap<u64, oneshot::Sender<Result<Via, String>>>>,
    server_state: std::sync::Mutex<&'static str>,
    presence: std::sync::Mutex<Vec<DevicePresence>>,
    settings: std::sync::Mutex<Value>,
    pair_confirm: std::sync::Mutex<Option<oneshot::Sender<bool>>>,
    pair_task: std::sync::Mutex<Option<tokio::task::AbortHandle>>,
    events: broadcast::Sender<Value>,
    ui: UiSink,
    next_transfer: AtomicU64,
}

impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Service")
    }
}

/// `config.json` in the data dir (deployment-specific, never in the repo, ADR 0007):
/// `{"server_url": "...", "create_token": "..."}`.
fn load_config(dir: &Path) -> (Option<String>, Option<String>) {
    let Ok(raw) = std::fs::read(dir.join("config.json")) else {
        return (None, None);
    };
    let v: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
    let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
    (s("server_url"), s("create_token"))
}

impl Service {
    /// Loads or creates the device (keys wrapped with DPAPI) and the settings.
    pub fn open(ui: UiSink, events: broadcast::Sender<Value>) -> Result<Arc<Self>, &'static str> {
        let dir = data_dir().ok_or("no LOCALAPPDATA")?;
        std::fs::create_dir_all(&dir).map_err(|_| "data dir")?;
        let ks = Dpapi;
        let dev = match Device::load(&dir, &ks, now_ms()) {
            Ok(d) => d,
            Err(NetError::Io(std::io::ErrorKind::NotFound)) => {
                let name = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows PC".into());
                let d = Device::new(&name, platform::WINDOWS).map_err(|_| "keygen")?;
                d.save(&dir, &ks).map_err(|_| "save device")?;
                d
            }
            Err(_) => return Err("load device"),
        };
        let (server_url, token) = load_config(&dir);
        let client = server_url.as_deref().and_then(|u| {
            let ik = Arc::new(IdentityKey::from_secret(&dev.keys.ik.secret()));
            let c = Client::new(u, ik).ok()?;
            Some(match token.as_deref().map(CreateToken::new) {
                Some(Ok(t)) => c.with_create_token(t),
                _ => c,
            })
        });
        let mut settings = default_settings();
        if let Ok(raw) = std::fs::read(dir.join("settings.json"))
            && let Ok(Value::Object(saved)) = serde_json::from_slice::<Value>(&raw)
        {
            let _ = merge_settings(&mut settings, &saved);
        }
        let mgr = EndpointManager::new(
            &dev.keys.ik,
            Relay::Eu,
            Some(Box::new(|| {
                power::trim_working_set();
            })),
        );
        Ok(Arc::new(Self {
            dir,
            ks,
            dev: Mutex::new(dev),
            client,
            server_url,
            mgr,
            replay: Mutex::new(ReplayCache::default()),
            pending: Mutex::new(PendingSessions::default()),
            send_lock: Mutex::new(()),
            ws: Mutex::new(None),
            acks: Mutex::new(HashMap::new()),
            server_state: std::sync::Mutex::new("offline"),
            presence: std::sync::Mutex::new(Vec::new()),
            settings: std::sync::Mutex::new(settings),
            pair_confirm: std::sync::Mutex::new(None),
            pair_task: std::sync::Mutex::new(None),
            events,
            ui,
            next_transfer: AtomicU64::new(1),
        }))
    }

    /// Starts the background tasks. Call once, inside the runtime.
    pub async fn start(self: &Arc<Self>) {
        tokio::spawn(Arc::clone(&self.mgr).run_reaper());
        let hk = self.setting_str("hotkey");
        if hk != hotkey::DEFAULT_HOTKEY {
            (self.ui)(UiMsg::Hotkey(hk));
        }
        self.start_ws().await;
        self.refresh_menu().await;
    }

    pub async fn on_cmd(self: &Arc<Self>, cmd: Cmd) {
        match cmd {
            Cmd::SendClip(c) => match clip_items(c) {
                Ok(items) => {
                    let this = Arc::clone(self);
                    tokio::spawn(async move { this.send_and_report(None, items).await });
                }
                Err(code) => self.toast(
                    "Nothing sent",
                    &format!("The clipboard can't be sent ({code})."),
                ),
            },
            Cmd::SetDefaultIndex(i) => {
                let others = self.others().await;
                if let Some((id, _)) = others.get(i) {
                    self.update_settings(json!({"default_target": hex(&id.0)}));
                    self.refresh_menu().await;
                }
            }
        }
    }

    // ------------------------------------------------------------ helpers

    fn emit(&self, name: &str, data: Value) {
        let _ = self.events.send(json!({"event": name, "data": data}));
    }

    fn toast(&self, title: &str, body: &str) {
        (self.ui)(UiMsg::Toast {
            title: title.into(),
            body: body.into(),
            image: None,
        });
    }

    fn setting_str(&self, k: &str) -> String {
        lk(&self.settings)
            .get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    }

    fn setting_bool(&self, path: &[&str]) -> bool {
        let s = lk(&self.settings);
        let mut v = &*s;
        for p in path {
            match v.get(p) {
                Some(x) => v = x,
                None => return true,
            }
        }
        v.as_bool().unwrap_or(true)
    }

    fn setting_u64(&self, k: &str, default: u64) -> u64 {
        lk(&self.settings)
            .get(k)
            .and_then(Value::as_u64)
            .unwrap_or(default)
    }

    fn update_settings(&self, patch: Value) -> Value {
        let mut s = lk(&self.settings);
        if let Value::Object(m) = &patch {
            let _ = merge_settings(&mut s, m);
        }
        if let Ok(b) = serde_json::to_vec_pretty(&*s) {
            let _ = write_atomic(&self.dir.join("settings.json"), &b);
        }
        s.clone()
    }

    fn save(&self, dev: &Device) {
        let _ = dev.save(&self.dir, &self.ks);
    }

    /// Records the server state and sends the full `status` event (docs/ipc.md:
    /// same shape as the `status` result; the UI replaces its state with it).
    async fn set_server(&self, state: &'static str) {
        let changed = {
            let mut s = lk(&self.server_state);
            let c = *s != state;
            *s = state;
            c
        };
        if changed {
            let st = self.status().await;
            self.emit("status", st);
        }
    }

    /// Other members, in log order.
    async fn others(&self) -> Vec<(EndpointId, (String, u64))> {
        let dev = self.dev.lock().await;
        let me = dev.id();
        dev.log
            .as_ref()
            .map(|l| {
                l.members()
                    .iter()
                    .filter(|(id, _)| **id != me)
                    .map(|(id, d)| (*id, (d.name.clone(), d.platform)))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn is_online(&self, id: &EndpointId) -> bool {
        lk(&self.presence).iter().any(|p| p.id == *id && p.online)
    }

    async fn refresh_menu(&self) {
        let others = self.others().await;
        let def = self.setting_str("default_target");
        let model = MenuModel {
            devices: others
                .iter()
                .map(|(id, (name, _))| DeviceItem {
                    name: name.clone(),
                    online: self.is_online(id),
                })
                .collect(),
            targets: others.iter().map(|(_, (n, _))| n.clone()).collect(),
            default_target: others
                .iter()
                .position(|(id, _)| hex(&id.0) == def)
                .or(if others.is_empty() { None } else { Some(0) }),
        };
        (self.ui)(UiMsg::Menu(model));
    }

    async fn history_store(&self) -> Option<history::Store> {
        let dev = self.dev.lock().await;
        history::Store::open(&self.dir.join("history.db"), &dev.keys.hk).ok()
    }

    fn retention(&self) -> Retention {
        Retention {
            max_age_ms: self
                .setting_u64("history_days", 30)
                .saturating_mul(24 * 3600 * 1000),
            max_items: self.setting_u64("history_items", 200),
        }
    }

    // ------------------------------------------------------------ server

    async fn start_ws(self: &Arc<Self>) {
        let Some(client) = &self.client else { return };
        let Some(gid) = self.dev.lock().await.group_id() else {
            return;
        };
        let mut ws = self.ws.lock().await;
        if ws.is_some() {
            return;
        }
        let (h, mut rx) = client.websocket(gid, WsConfig::default());
        *ws = Some(h);
        drop(ws);
        self.set_server("connecting").await;
        let this = Arc::clone(self);
        tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                this.on_ws_event(ev).await;
            }
            *this.ws.lock().await = None;
            this.set_server("offline").await;
        });
    }

    async fn on_ws_event(self: &Arc<Self>, ev: Event) {
        match ev {
            Event::Connected => {
                self.set_server("connected").await;
                let after = self
                    .dev
                    .lock()
                    .await
                    .head()
                    .map(|h| h.seq)
                    .unwrap_or_default();
                if let Some(h) = self.ws.lock().await.as_ref() {
                    let _ = h.log_get(after).await;
                    let _ = h.presence().await;
                }
                power::trim_working_set();
            }
            Event::Disconnected(_) | Event::ConnectFailed(_) => self.set_server("connecting").await,
            Event::Wake { env } => {
                let this = Arc::clone(self);
                tokio::spawn(async move { this.handle_wake(env).await });
            }
            Event::Ack { id, via } => {
                if let Some(tx) = self.acks.lock().await.remove(&id) {
                    let _ = tx.send(Ok(via));
                }
            }
            Event::Err { id: Some(id), code } => {
                if let Some(tx) = self.acks.lock().await.remove(&id) {
                    let _ = tx.send(Err(code.as_str().to_owned()));
                }
            }
            Event::NotSent { id } => {
                if let Some(tx) = self.acks.lock().await.remove(&id) {
                    let _ = tx.send(Err("not-sent".into()));
                }
            }
            Event::Presence { devices, .. } => {
                *lk(&self.presence) = devices;
                self.refresh_menu().await;
            }
            Event::Log { records, head, .. } => self.apply_log(records, head).await,
            Event::Bye { .. } | Event::Ended(_) => self.set_server("offline").await,
            Event::Err { id: None, .. } => {}
        }
    }

    async fn apply_log(self: &Arc<Self>, records: Vec<Vec<u8>>, head: Head) {
        let mut dev = self.dev.lock().await;
        let Some(mut log) = dev.log.clone() else {
            return;
        };
        let before: Vec<EndpointId> = log.members().keys().copied().collect();
        match net::server::apply(&mut log, &records, &head, now_ms()) {
            Ok(true) => {
                let me = dev.id();
                // (id, name, platform, name of the member who signed the add)
                let added: Vec<(EndpointId, String, u64, String)> = log
                    .members()
                    .iter()
                    .filter(|(id, _)| **id != me && !before.contains(id))
                    .map(|(id, d)| {
                        let by = log
                            .records()
                            .iter()
                            .rev()
                            .find(|r| r.body.subject == *id && matches!(r.body.op, Op::Add(_)))
                            .and_then(|r| log.members().get(&r.signer))
                            .map(|m| m.name.clone())
                            .unwrap_or_default();
                        (*id, d.name.clone(), d.platform, by)
                    })
                    .collect();
                let local_seq = log.head().map(|h| h.seq).unwrap_or_default();
                dev.log = Some(log);
                self.save(&dev);
                drop(dev);
                for (id, name, p, by) in added {
                    self.emit(
                        "group.alert",
                        json!({"kind": "device-added", "id": hex(&id.0), "name": name, "platform": platform_str(p), "by_name": by}),
                    );
                    self.toast(
                        "New device in your Warpshot group",
                        &format!(
                            "\"{name}\" was added. If this wasn't you, remove it in Settings."
                        ),
                    );
                }
                self.refresh_menu().await;
                if local_seq < head.seq
                    && let Some(h) = self.ws.lock().await.as_ref()
                {
                    let _ = h.log_get(local_seq).await;
                }
            }
            Ok(false) => {}
            Err(NetError::Fork) => {
                drop(dev);
                self.emit("group.fork", json!({}));
                self.toast(
                    "Warpshot security alert",
                    "Your device group's history was forked. Transfers are stopped; pair your devices again.",
                );
            }
            Err(_) => {}
        }
    }

    /// Wakes `target` with `env`: over the WebSocket when connected, else REST.
    async fn wake(&self, target: &EndpointId, env: &[u8]) -> Result<Via, String> {
        let gid = self.dev.lock().await.group_id().ok_or("not-paired")?;
        let rx = {
            let ws = self.ws.lock().await;
            match ws.as_ref().filter(|h| h.is_connected()) {
                Some(h) => {
                    let mut acks = self.acks.lock().await;
                    match h.wake(target, env, WAKE_TTL).await {
                        Ok(id) => {
                            let (tx, rx) = oneshot::channel();
                            acks.insert(id, tx);
                            Some(rx)
                        }
                        Err(_) => None,
                    }
                }
                None => None,
            }
        };
        if let Some(rx) = rx {
            return match tokio::time::timeout(Duration::from_secs(15), rx).await {
                Ok(Ok(r)) => r,
                _ => Err("timeout".into()),
            };
        }
        let client = self.client.as_ref().ok_or("no-server")?;
        client
            .wake(&gid, target, env, WAKE_TTL)
            .await
            .map_err(|e| e.to_string())
    }

    // ------------------------------------------------------------ receive

    async fn handle_wake(self: &Arc<Self>, env: Vec<u8>) {
        let mut synced = false;
        let (sender, action) = loop {
            let res = {
                let dev = self.dev.lock().await;
                let mut replay = self.replay.lock().await;
                flow::open_wake(&dev, &env, now_ms(), &mut replay)
            };
            match res {
                Ok(v) => break v,
                Err(WakeError::NeedSync) if !synced => {
                    synced = true;
                    if self.pull_log().await.is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        };
        match action {
            WakeAction::GroupChanged => {
                let _ = self.pull_log().await;
            }
            WakeAction::Connect { session, dial, .. } => {
                let res = self.receive(sender, session, dial).await;
                if let Err(e) = res {
                    self.toast(
                        "Transfer failed",
                        &format!("Couldn't receive ({}).", net_code(&e)),
                    );
                }
            }
        }
    }

    async fn pull_log(self: &Arc<Self>) -> Result<(), NetError> {
        let client = self.client.as_ref().ok_or(NetError::State("no server"))?;
        let mut dev = self.dev.lock().await;
        let Some(mut log) = dev.log.clone() else {
            return Ok(());
        };
        if net::server::pull(client, &mut log, now_ms()).await? {
            dev.log = Some(log);
            self.save(&dev);
        }
        Ok(())
    }

    async fn receive(
        self: &Arc<Self>,
        sender: EndpointId,
        session: [u8; 16],
        dial: warpshot_core::wake::DialInfo,
    ) -> Result<(), NetError> {
        let (ep, _lease) = self.mgr.acquire().await?;
        let mut log = self
            .dev
            .lock()
            .await
            .log
            .clone()
            .ok_or(NetError::State("not paired"))?;
        let mut s = flow::answer_connect(&ep, &log, &sender, session, &dial).await?;
        if s.sync_logs(&mut log, now_ms()).await? {
            let mut dev = self.dev.lock().await;
            dev.log = Some(log.clone());
            self.save(&dev);
        }
        let dir = PathBuf::from(self.setting_str("save_dir"));
        std::fs::create_dir_all(&dir)?;
        let policy = Policy {
            dir,
            max_size: self
                .setting_u64("ask_above_mb", MAX_RECEIVE_DEFAULT_MB)
                .saturating_mul(1 << 20),
            accept_large: false,
        };
        let items = s.receive(&policy, |_| true).await?;
        let peer_name = log
            .members()
            .get(&sender)
            .map(|d| d.name.clone())
            .unwrap_or_else(|| "your device".into());
        self.on_received(&sender, &peer_name, items).await;
        Ok(())
    }

    async fn on_received(&self, peer: &EndpointId, peer_name: &str, items: Vec<Received>) {
        if items.is_empty() {
            return;
        }
        if self.setting_bool(&["on_receive", "history"])
            && let Some(mut h) = self.history_store().await
        {
            let keep = self.retention();
            for r in &items {
                let path = r.path.as_ref().map(|p| p.display().to_string());
                let _ = h.add(
                    now_ms(),
                    Direction::In,
                    peer,
                    r.item.kind,
                    r.item.size,
                    true,
                    Some(&r.item.name)
                        .filter(|n| !n.is_empty())
                        .map(String::as_str),
                    path.as_deref(),
                    r.item.text.as_deref(),
                    keep,
                );
            }
        }
        let clip = self.setting_bool(&["on_receive", "clipboard"]);
        let notify = self.setting_bool(&["on_receive", "notify"]);
        let title = format!("From {peer_name}");
        let files: Vec<PathBuf> = items.iter().filter_map(|r| r.path.clone()).collect();
        let first = items.first().map(|r| (&r.item, r.path.clone()));
        match first {
            Some((item, _)) if items.len() == 1 && item.kind == wx::kind::TEXT => {
                let text = item.text.clone().unwrap_or_default();
                if notify {
                    let preview: String = text.chars().take(120).collect();
                    (self.ui)(UiMsg::Toast {
                        title,
                        body: if clip {
                            format!("Copied: {preview}")
                        } else {
                            preview
                        },
                        image: None,
                    });
                }
                if clip {
                    (self.ui)(UiMsg::ClipText(text));
                }
            }
            Some((item, Some(path))) if items.len() == 1 && item.kind == wx::kind::IMAGE => {
                if clip {
                    (self.ui)(UiMsg::ClipImage(path.clone()));
                }
                if notify {
                    (self.ui)(UiMsg::Toast {
                        title,
                        body: if clip {
                            "Image copied to the clipboard and saved.".into()
                        } else {
                            "Image saved.".into()
                        },
                        image: Some(path),
                    });
                }
            }
            _ => {
                if clip && !files.is_empty() {
                    (self.ui)(UiMsg::ClipFiles(files.clone()));
                }
                if notify {
                    self.toast(
                        &title,
                        &format!(
                            "{} item(s) saved to {}.",
                            items.len(),
                            self.setting_str("save_dir")
                        ),
                    );
                }
            }
        }
        self.emit("history.changed", json!({}));
        let n = self.next_transfer.fetch_add(1, Ordering::Relaxed);
        self.emit(
            "transfer.done",
            json!({"transfer": n.to_string(), "ok": true}),
        );
        power::trim_working_set();
    }

    // ------------------------------------------------------------ send

    async fn resolve_target(&self, target: Option<&str>) -> Result<EndpointId, &'static str> {
        let others = self.others().await;
        if others.is_empty() {
            return Err("not-paired");
        }
        let want = target
            .map(str::to_owned)
            .unwrap_or_else(|| self.setting_str("default_target"));
        if let Some(id) = parse_id(&want)
            && others.iter().any(|(o, _)| *o == id)
        {
            return Ok(id);
        }
        if target.is_some() {
            return Err("unknown-device");
        }
        // Default: the first phone, else the first device.
        others
            .iter()
            .find(|(_, (_, p))| *p == platform::ANDROID)
            .or(others.first())
            .map(|(id, _)| *id)
            .ok_or("not-paired")
    }

    async fn send_and_report(
        self: &Arc<Self>,
        target: Option<String>,
        items: Vec<OutItem>,
    ) -> bool {
        let n = self.next_transfer.fetch_add(1, Ordering::Relaxed);
        let res = self.send(target.as_deref(), items).await;
        let (ok, code) = match &res {
            Ok(_) => (true, None),
            Err(c) => (false, Some(c.clone())),
        };
        self.emit(
            "transfer.done",
            json!({"transfer": n.to_string(), "ok": ok, "code": code}),
        );
        match res {
            Ok(to) => {
                // Hotkey sends have no other UI: confirm quietly.
                let name = self
                    .others()
                    .await
                    .into_iter()
                    .find(|(id, _)| *id == to)
                    .map(|(_, (n, _))| n)
                    .unwrap_or_else(|| "your device".into());
                self.toast("Sent", &format!("Sent to {name}."));
            }
            Err(c) => {
                let body = match c.as_str() {
                    "offline" => {
                        "The device is offline and can't be woken up right now.".to_owned()
                    }
                    "no-answer" => "The device didn't respond (battery restrictions?).".to_owned(),
                    "not-paired" => "Pair a device first (tray icon → Settings).".to_owned(),
                    other => format!("Sending failed ({other})."),
                };
                self.toast("Not sent", &body);
            }
        }
        power::trim_working_set();
        ok
    }

    /// Sends items: wake the target, then wait for it to dial in (§7.4). Returns the target.
    async fn send(
        self: &Arc<Self>,
        target: Option<&str>,
        items: Vec<OutItem>,
    ) -> Result<EndpointId, String> {
        let _one_at_a_time = self.send_lock.lock().await;
        let target = self.resolve_target(target).await?;
        let (ep, _lease) = self.mgr.acquire().await.map_err(|e| net_code(&e))?;
        let (env, log) = {
            let dev = self.dev.lock().await;
            let session = self
                .pending
                .lock()
                .await
                .insert(target, items.clone())
                .map_err(|e| net_code(&e))?;
            (
                flow::connect_wake(&ep, &dev, &target, session, &items, now_ms())
                    .map_err(|e| net_code(&e))?,
                dev.log.clone().ok_or("not-paired")?,
            )
        };
        let via = self.wake(&target, &env).await?;
        if via == Via::None {
            return Err("offline".into());
        }
        let deadline = tokio::time::Instant::now()
            .checked_add(flow::PENDING_TTL)
            .ok_or("time")?;
        loop {
            let inc = tokio::time::timeout_at(deadline, ep.accept())
                .await
                .map_err(|_| "no-answer")?
                .ok_or("no-answer")?;
            let Ok(acc) = inc.accept() else { continue };
            let Ok(conn) = acc.await else { continue };
            if conn.alpn() != wx::ALPN {
                net::close(&conn, wx::code::PROTOCOL);
                continue;
            }
            let Ok(mut s) = nx::accept(&ep, conn, &log).await else {
                continue;
            };
            let Some(p) = self.pending.lock().await.take(&s.hello_session, &s.peer) else {
                net::close(&s.conn, wx::code::PROTOCOL);
                continue;
            };
            // §8.5: both peers run the log sync step before any transfer.
            let mut synced = log.clone();
            if s.sync_logs(&mut synced, now_ms())
                .await
                .map_err(|e| net_code(&e))?
            {
                let mut dev = self.dev.lock().await;
                dev.log = Some(synced);
                self.save(&dev);
            }
            let sent: Vec<Item> = p.items.iter().map(|o| o.item.clone()).collect();
            let results = tokio::time::timeout(Duration::from_secs(3600), s.send_items(p.items))
                .await
                .map_err(|_| "timeout")?
                .map_err(|e| net_code(&e))?;
            if let Some(mut h) = self.history_store().await {
                let keep = self.retention();
                for it in &sent {
                    let ok = results.iter().any(|(id, ok)| *id == it.id && *ok);
                    let _ = h.add(
                        now_ms(),
                        Direction::Out,
                        &target,
                        it.kind,
                        it.size,
                        ok,
                        Some(it.name.as_str()).filter(|n| !n.is_empty()),
                        None,
                        it.text.as_deref(),
                        keep,
                    );
                }
            }
            self.emit("history.changed", json!({}));
            return if results.iter().all(|(_, ok)| *ok) {
                Ok(target)
            } else {
                Err("rejected".into())
            };
        }
    }

    // ------------------------------------------------------------ pairing

    fn pair_cancel(&self) {
        if let Some(t) = lk(&self.pair_task).take() {
            t.abort();
        }
        lk(&self.pair_confirm).take();
    }

    async fn pair_start(self: &Arc<Self>) -> Result<Value, RpcError> {
        self.pair_cancel();
        let (Some(url), Some(_)) = (self.server_url.clone(), self.client.as_ref()) else {
            return Err(fail("no-server"));
        };
        let (ep, lease) = self.mgr.acquire().await.map_err(|e| fail(net_code(&e)))?;
        // Pairing works on its own copy of the device so the shared state stays usable.
        let pdev = Device::load(&self.dir, &self.ks, now_ms()).map_err(|_| fail("storage"))?;
        let window = Window::open(
            pdev.id(),
            net::dial_info(&ep),
            pdev.name.clone(),
            pdev.group_id(),
            now_ms() / 1000,
        )
        .map_err(|_| fail("internal"))?
        .with_server(url);
        let out = json!({
            "qr_text": window.qr_text(),
            "expires_at": window.expires_at_secs().saturating_mul(1000),
        });
        let this = Arc::clone(self);
        let task = tokio::spawn(async move {
            let _lease = lease;
            let ev = match this.run_pair(&ep, window, pdev).await {
                Ok(peer) => ("pair.done", json!({"peer_id": hex(&peer.0)})),
                Err(e) => {
                    let code = match e {
                        NetError::Timeout
                        | NetError::Pair(PairError::Expired | PairError::Used) => "expired",
                        NetError::Pair(PairError::Proof) => "proof",
                        NetError::Rejected | NetError::Declined(_) => "rejected",
                        _ => "network",
                    };
                    ("pair.failed", json!({"code": code}))
                }
            };
            this.emit(ev.0, ev.1);
        });
        *lk(&self.pair_task) = Some(task.abort_handle());
        Ok(out)
    }

    async fn run_pair(
        self: &Arc<Self>,
        ep: &iroh::Endpoint,
        mut window: Window,
        pdev: Device,
    ) -> Result<EndpointId, NetError> {
        let deadline =
            Duration::from_secs(window.expires_at_secs().saturating_sub(now_ms() / 1000));
        let conn = tokio::time::timeout(deadline, async {
            loop {
                let inc = ep.accept().await.ok_or(NetError::Bind)?;
                let Ok(acc) = inc.accept() else { continue };
                let Ok(conn) = acc.await else { continue };
                if conn.alpn() == warpshot_core::pair::ALPN {
                    return Ok::<_, NetError>(conn);
                }
                net::close(&conn, wx::code::PROTOCOL);
            }
        })
        .await
        .map_err(|_| NetError::Timeout)??;
        let ask = Arc::clone(self);
        let sub = Arc::clone(self);
        let paired = net::pair::display(
            ep,
            conn,
            &mut window,
            &pdev,
            now_ms(),
            move |s: PeerSummary| async move { ask.ask_sas(s).await },
            move |records: Vec<Vec<u8>>| async move {
                let c = sub.client.as_ref().ok_or(NetError::State("no server"))?;
                net::server::submit(c, &records).await.map(|_| ())
            },
        )
        .await?;
        {
            let mut dev = self.dev.lock().await;
            dev.log = Some(paired.log);
            self.save(&dev);
        }
        if self.setting_str("default_target").is_empty() {
            self.update_settings(json!({"default_target": hex(&paired.peer.0)}));
        }
        self.start_ws().await;
        if let Some(h) = self.ws.lock().await.as_ref() {
            let _ = h.presence().await;
        }
        self.refresh_menu().await;
        let st = self.status().await;
        self.emit("status", st);
        Ok(paired.peer)
    }

    async fn ask_sas(&self, s: PeerSummary) -> bool {
        let (tx, rx) = oneshot::channel();
        *lk(&self.pair_confirm) = Some(tx);
        self.emit(
            "pair.sas",
            json!({"sas": s.sas, "peer_name": s.device.name, "peer_platform": platform_str(s.device.platform)}),
        );
        matches!(
            tokio::time::timeout(Duration::from_secs(90), rx).await,
            Ok(Ok(true))
        )
    }

    // ------------------------------------------------------------ membership

    async fn append(&self, subject: EndpointId, op: Op) -> Result<(), RpcError> {
        let client = self.client.as_ref().ok_or_else(|| fail("no-server"))?;
        let mut dev = self.dev.lock().await;
        let mut log = dev.log.clone().ok_or_else(|| fail("not-paired"))?;
        let (seq, prev) = log.next_position();
        let body = RecordBody {
            group_id: log.group_id(),
            seq,
            prev,
            created_at: now_ms(),
            subject,
            op,
        };
        let raw = sign_record(&dev.keys.ik, &body);
        log.append(&raw, now_ms())
            .map_err(|_| fail("not-allowed"))?;
        // The server orders appends (CAS on the head); keep the record only if it took it.
        net::server::submit(client, &[raw])
            .await
            .map_err(|e| fail(net_code(&e)))?;
        dev.log = Some(log);
        self.save(&dev);
        Ok(())
    }

    // ------------------------------------------------------------ IPC

    async fn status(&self) -> Value {
        let dev = self.dev.lock().await;
        json!({
            "device": {"id": hex(&dev.id().0), "name": dev.name, "platform": platform_str(dev.platform)},
            "paired": dev.log.as_ref().is_some_and(|l| l.members().len() > 1),
            "server": if self.client.is_none() { "offline" } else { *lk(&self.server_state) },
            "version": env!("CARGO_PKG_VERSION"),
        })
    }

    pub async fn rpc(self: &Arc<Self>, method: &str, p: Value) -> Result<Value, RpcError> {
        let s = |k: &str| p.get(k).and_then(Value::as_str);
        match method {
            "ping" => Ok(json!("pong")),
            "agent.version" => Ok(json!(env!("CARGO_PKG_VERSION"))),
            "status" => Ok(self.status().await),
            "devices.list" => {
                let dev = self.dev.lock().await;
                let me = dev.id();
                let def = self.setting_str("default_target");
                let pres = lk(&self.presence).clone();
                let list: Vec<Value> = dev
                    .log
                    .as_ref()
                    .map(|l| {
                        l.members()
                            .iter()
                            .map(|(id, d)| {
                                let pr = pres.iter().find(|x| x.id == *id);
                                json!({
                                    "id": hex(&id.0),
                                    "name": d.name,
                                    "platform": platform_str(d.platform),
                                    "me": *id == me,
                                    "online": *id == me || pr.is_some_and(|x| x.online),
                                    "last_seen": pr.and_then(|x| x.last_seen),
                                    "push": pr.is_some_and(|x| x.push),
                                    "default_target": hex(&id.0) == def,
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                Ok(Value::Array(list))
            }
            "devices.rename" => {
                let name = s("name")
                    .map(str::trim)
                    .filter(|n| !n.is_empty() && n.len() <= 64)
                    .ok_or_else(|| bad("name"))?
                    .to_owned();
                let (me, mut info, paired) = {
                    let dev = self.dev.lock().await;
                    (dev.id(), dev.info(), dev.log.is_some())
                };
                info.name.clone_from(&name);
                if paired {
                    self.append(me, Op::Update(info)).await?;
                }
                let mut dev = self.dev.lock().await;
                dev.name = name;
                self.save(&dev);
                Ok(json!({}))
            }
            "devices.remove" | "group.not_me" => {
                let id = s("id").and_then(parse_id).ok_or_else(|| bad("id"))?;
                let reason = match (method, s("reason")) {
                    ("group.not_me", _) | (_, Some("not-me")) => RemoveReason::NotMe,
                    (_, Some("lost-or-stolen")) => RemoveReason::LostOrStolen,
                    (_, Some("user") | None) => RemoveReason::User,
                    _ => return Err(bad("reason")),
                };
                self.append(id, Op::Remove(reason)).await?;
                self.refresh_menu().await;
                Ok(json!({}))
            }
            "devices.set_default" => {
                let id = s("id").and_then(parse_id).ok_or_else(|| bad("id"))?;
                self.update_settings(json!({"default_target": hex(&id.0)}));
                self.refresh_menu().await;
                Ok(json!({}))
            }
            "pair.start" => self.pair_start().await,
            "pair.confirm" => {
                let accept = p
                    .get("accept")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| bad("accept"))?;
                if let Some(tx) = lk(&self.pair_confirm).take() {
                    let _ = tx.send(accept);
                }
                Ok(json!({}))
            }
            "pair.cancel" => {
                self.pair_cancel();
                Ok(json!({}))
            }
            "settings.get" => Ok(lk(&self.settings).clone()),
            "settings.set" => {
                let Value::Object(m) = &p else {
                    return Err(bad("settings"));
                };
                let mut probe = lk(&self.settings).clone();
                merge_settings(&mut probe, m)?;
                if let Some(Value::String(h)) = m.get("hotkey")
                    && let Ok(hk) = Hotkey::parse(h)
                {
                    (self.ui)(UiMsg::Hotkey(hk.to_string()));
                }
                if let Some(Value::Bool(on)) = m.get("autostart") {
                    let _ = if *on {
                        crate::autostart::enable()
                    } else {
                        crate::autostart::disable()
                    };
                }
                let out = self.update_settings(p.clone());
                self.refresh_menu().await;
                Ok(out)
            }
            "hotkey.check" => {
                let hk = s("hotkey").map(Hotkey::parse);
                Ok(match hk {
                    Some(Ok(hk)) => {
                        let c = hotkey::altgr_conflict_current(&hk);
                        json!({"valid": true, "conflict": c.is_some(), "produces": c.map(|o| o.to_string())})
                    }
                    _ => json!({"valid": false, "conflict": false}),
                })
            }
            "history.list" => {
                let before = p.get("before").and_then(Value::as_u64);
                let limit = p
                    .get("limit")
                    .and_then(Value::as_u64)
                    .unwrap_or(50)
                    .min(200);
                let h = self.history_store().await.ok_or_else(|| fail("storage"))?;
                let rows = h
                    .list(before, u32::try_from(limit).unwrap_or(50))
                    .map_err(|_| fail("storage"))?;
                Ok(Value::Array(
                    rows.into_iter()
                        .map(|e| {
                            json!({
                                "id": e.id.to_string(),
                                "ts": e.ts,
                                "direction": if e.direction == Direction::In { "in" } else { "out" },
                                "peer": hex(&e.peer.0),
                                "kind": match e.kind { wx::kind::TEXT => "text", wx::kind::IMAGE => "image", _ => "file" },
                                "name": e.name.or(e.text.map(|t| t.chars().take(80).collect())),
                                "size": e.size,
                                "path": e.path,
                                "ok": e.ok,
                            })
                        })
                        .collect(),
                ))
            }
            "history.reveal" | "history.delete" => {
                let id: i64 = s("id")
                    .and_then(|v| v.parse().ok())
                    .ok_or_else(|| bad("id"))?;
                let h = self.history_store().await.ok_or_else(|| fail("storage"))?;
                if method == "history.delete" {
                    h.delete(id).map_err(|_| fail("storage"))?;
                    return Ok(json!({}));
                }
                let path = h
                    .get(id)
                    .ok()
                    .flatten()
                    .and_then(|e| e.path)
                    .ok_or_else(|| fail("not-found"))?;
                // Shows the file selected in Explorer; never opens or runs it.
                use std::os::windows::process::CommandExt;
                std::process::Command::new("explorer.exe")
                    .raw_arg(format!("/select,\"{path}\""))
                    .spawn()
                    .map_err(|_| fail("internal"))?;
                Ok(json!({}))
            }
            "send.text" | "send.files" => {
                let items = if method == "send.text" {
                    let t = s("text").ok_or_else(|| bad("text"))?;
                    clip_items(ClipContent::Text(t.to_owned())).map_err(fail)?
                } else {
                    let paths: Vec<PathBuf> = p
                        .get("paths")
                        .and_then(Value::as_array)
                        .ok_or_else(|| bad("paths"))?
                        .iter()
                        .filter_map(Value::as_str)
                        .map(PathBuf::from)
                        .collect();
                    clip_items(ClipContent::Files(paths)).map_err(fail)?
                };
                let target = s("target").map(str::to_owned);
                let n = self.next_transfer.load(Ordering::Relaxed);
                let this = Arc::clone(self);
                tokio::spawn(async move { this.send_and_report(target, items).await });
                Ok(json!({"transfer": n.to_string()}))
            }
            "debug.counters" => {
                let c = self
                    .client
                    .as_ref()
                    .map(Client::counters)
                    .unwrap_or_default();
                Ok(json!({
                    "ws_bytes_in": c.bytes_in, "ws_bytes_out": c.bytes_out,
                    "http_requests": c.http_requests, "ws_connects": c.ws_connects,
                    "ws_disconnects": c.ws_disconnects, "pings": c.pings, "pongs": c.pongs,
                    "missed_pongs": c.missed_pongs,
                    "transfers": self.next_transfer.load(Ordering::Relaxed).saturating_sub(1),
                    "endpoint_open": self.mgr.is_open().await,
                }))
            }
            _ => Err(RpcError::method_not_found()),
        }
    }
}

/// Pipe handler wrapper.
#[derive(Debug)]
pub struct Rpc(pub Arc<Service>);

impl pipe::Handler for Rpc {
    async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        self.0.rpc(method, params).await
    }
}

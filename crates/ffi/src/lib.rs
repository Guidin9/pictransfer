//! UniFFI surface of the Warpshot core for the Android app.
//!
//! Kotlin supplies the Android Keystore wrapper and the pairing confirmation
//! UI; the core does pairing, wake handling and transfers. Errors carry kinds
//! and codes only — never content, names or addresses.

use std::{path::PathBuf, sync::Arc, time::Duration};

use tokio::sync::Mutex;
use warpshot_core::{
    b64u,
    client::Client,
    keys::{EndpointId, KeyError, Keystore},
    log::platform,
    net::{
        self, NetError, Relay,
        flow::{self, PendingSessions, WakeAction},
        manager::EndpointManager,
        store::{Device, now_ms},
        xfer::{self as nx, OutItem, Policy, Source},
    },
    pair::QrPayload,
    wake::{ReplayCache, WakeError},
};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

#[derive(Debug, uniffi::Error)]
pub enum WarpError {
    NotPaired,
    Storage,
    Invalid,
    Rejected,
    Offline,
    Network { code: u32 },
    Server { code: String },
    Keystore,
}

impl std::fmt::Display for WarpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for WarpError {}

impl From<NetError> for WarpError {
    fn from(e: NetError) -> Self {
        match e {
            NetError::Server(c) => WarpError::Server {
                code: c.to_string(),
            },
            NetError::Rejected | NetError::Declined(_) => WarpError::Rejected,
            NetError::Io(_) | NetError::State(_) => WarpError::Storage,
            other => WarpError::Network {
                code: other.close_code(),
            },
        }
    }
}

/// Android Keystore wrapper implemented in Kotlin (AES-GCM key, StrongBox if present).
#[uniffi::export(foreign)]
pub trait PlatformKeystore: Send + Sync {
    fn wrap(&self, label: String, plain: Vec<u8>) -> Result<Vec<u8>, WarpError>;
    fn unwrap(&self, label: String, wrapped: Vec<u8>) -> Result<Vec<u8>, WarpError>;
}

/// Pairing confirmation UI (§5.3 step 6). Blocks until the user decides.
#[uniffi::export(foreign)]
pub trait PairConfirm: Send + Sync {
    fn confirm(&self, sas: String, peer_name: String, peer_platform: u64) -> bool;
}

struct KsAdapter(Arc<dyn PlatformKeystore>);

impl Keystore for KsAdapter {
    fn wrap(&self, label: &str, plain: &[u8]) -> Result<Vec<u8>, KeyError> {
        self.0
            .wrap(label.to_owned(), plain.to_vec())
            .map_err(|_| KeyError::Keystore)
    }
    fn unwrap(&self, label: &str, wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        self.0
            .unwrap(label.to_owned(), wrapped.to_vec())
            .map(Zeroizing::new)
            .map_err(|_| KeyError::Keystore)
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct DeviceEntry {
    pub id: String,
    pub name: String,
    pub platform: u64,
    pub me: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ReceivedItem {
    pub id: u32,
    pub kind: u64,
    pub name: String,
    pub mime: String,
    pub size: u64,
    /// Path inside the inbox directory; Kotlin moves it to MediaStore.
    pub path: Option<String>,
    pub text: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct OutgoingFile {
    pub path: String,
}

/// The server URL carried in a pairing QR code (needed before [`Warpshot::open`]
/// on a fresh install), or `None` if the text is not a valid code or has none.
#[uniffi::export]
pub fn qr_server_url(qr_text: String) -> Option<String> {
    QrPayload::parse(qr_text.trim()).ok().and_then(|q| q.server)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn parse_id(s: &str) -> Result<EndpointId, WarpError> {
    if s.len() != 64 {
        return Err(WarpError::Invalid);
    }
    let mut id = [0u8; 32];
    for (b, pair) in id.iter_mut().zip(s.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| WarpError::Invalid)?;
        *b = u8::from_str_radix(pair, 16).map_err(|_| WarpError::Invalid)?;
    }
    Ok(EndpointId(id))
}

#[derive(uniffi::Object)]
pub struct Warpshot {
    dir: PathBuf,
    ks: KsAdapter,
    dev: Mutex<Device>,
    client: Client,
    mgr: Arc<EndpointManager>,
    replay: Mutex<ReplayCache>,
    pending: Mutex<PendingSessions>,
    rt: tokio::runtime::Runtime,
}

impl std::fmt::Debug for Warpshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Warpshot")
    }
}

impl Warpshot {
    async fn save(&self, dev: &Device) -> Result<(), WarpError> {
        dev.save(&self.dir, &self.ks)
            .map_err(|_| WarpError::Storage)
    }

    async fn pull_log(&self) -> Result<(), WarpError> {
        let mut dev = self.dev.lock().await;
        let Some(mut log) = dev.log.clone() else {
            return Err(WarpError::NotPaired);
        };
        if net::server::pull(&self.client, &mut log, now_ms()).await? {
            dev.log = Some(log);
            self.save(&dev).await?;
        }
        Ok(())
    }
}

#[uniffi::export]
impl Warpshot {
    /// Loads the device from `dir`, or creates it (keys wrapped by the Keystore).
    #[uniffi::constructor]
    pub fn open(
        dir: String,
        name: String,
        server_url: String,
        keystore: Arc<dyn PlatformKeystore>,
    ) -> Result<Arc<Self>, WarpError> {
        let dir = PathBuf::from(dir);
        let ks = KsAdapter(keystore);
        let dev = match Device::load(&dir, &ks, now_ms()) {
            Ok(d) => d,
            Err(NetError::Io(std::io::ErrorKind::NotFound)) => {
                let d = Device::new(&name, platform::ANDROID).map_err(|_| WarpError::Storage)?;
                d.save(&dir, &ks).map_err(|_| WarpError::Storage)?;
                d
            }
            Err(_) => return Err(WarpError::Storage),
        };
        let ik = Arc::new(warpshot_core::keys::IdentityKey::from_secret(
            &dev.keys.ik.secret(),
        ));
        let client = Client::new(&server_url, ik).map_err(|_| WarpError::Invalid)?;
        let mgr = EndpointManager::new(&dev.keys.ik, Relay::Eu, None);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| WarpError::Storage)?;
        let reaper = Arc::clone(&mgr);
        rt.spawn(reaper.run_reaper());
        Ok(Arc::new(Self {
            dir,
            ks,
            dev: Mutex::new(dev),
            client,
            mgr,
            replay: Mutex::new(ReplayCache::default()),
            pending: Mutex::new(PendingSessions::default()),
            rt,
        }))
    }
}

/// Exported async methods run on the object's own tokio runtime, so Kotlin
/// coroutines can await them without an async-compat shim.
#[uniffi::export]
impl Warpshot {
    pub async fn device_id(self: Arc<Self>) -> String {
        let this = Arc::clone(&self);
        self.rt
            .spawn(async move { this.device_id_impl().await })
            .await
            .unwrap_or_default()
    }

    pub async fn is_paired(self: Arc<Self>) -> bool {
        let this = Arc::clone(&self);
        self.rt
            .spawn(async move { this.is_paired_impl().await })
            .await
            .unwrap_or_default()
    }

    pub async fn devices(self: Arc<Self>) -> Vec<DeviceEntry> {
        let this = Arc::clone(&self);
        self.rt
            .spawn(async move { this.devices_impl().await })
            .await
            .unwrap_or_default()
    }

    pub async fn pair_scan(
        self: Arc<Self>,
        qr_text: String,
        ui: Arc<dyn PairConfirm>,
    ) -> Result<String, WarpError> {
        let this = Arc::clone(&self);
        self.rt
            .spawn(async move { this.pair_scan_impl(qr_text, ui).await })
            .await
            .map_err(|_| WarpError::Storage)?
    }

    pub async fn register_push_token(self: Arc<Self>, token: String) -> Result<(), WarpError> {
        let this = Arc::clone(&self);
        self.rt
            .spawn(async move { this.register_push_token_impl(token).await })
            .await
            .map_err(|_| WarpError::Storage)?
    }

    pub async fn handle_wake(
        self: Arc<Self>,
        envelope_b64u: String,
        inbox_dir: String,
    ) -> Result<Vec<ReceivedItem>, WarpError> {
        let this = Arc::clone(&self);
        self.rt
            .spawn(async move { this.handle_wake_impl(envelope_b64u, inbox_dir).await })
            .await
            .map_err(|_| WarpError::Storage)?
    }

    pub async fn send_text(self: Arc<Self>, target: String, text: String) -> Result<(), WarpError> {
        let this = Arc::clone(&self);
        self.rt
            .spawn(async move { this.send_text_impl(target, text).await })
            .await
            .map_err(|_| WarpError::Storage)?
    }

    pub async fn send_files(
        self: Arc<Self>,
        target: String,
        files: Vec<OutgoingFile>,
    ) -> Result<(), WarpError> {
        let this = Arc::clone(&self);
        self.rt
            .spawn(async move { this.send_files_impl(target, files).await })
            .await
            .map_err(|_| WarpError::Storage)?
    }

    pub async fn sync(self: Arc<Self>) -> Result<(), WarpError> {
        let this = Arc::clone(&self);
        self.rt
            .spawn(async move { this.sync_impl().await })
            .await
            .map_err(|_| WarpError::Storage)?
    }
}

impl Warpshot {
    async fn device_id_impl(&self) -> String {
        hex(&self.dev.lock().await.id().0)
    }

    async fn is_paired_impl(&self) -> bool {
        self.dev.lock().await.log.is_some()
    }

    async fn devices_impl(&self) -> Vec<DeviceEntry> {
        let dev = self.dev.lock().await;
        let me = dev.id();
        dev.log
            .as_ref()
            .map(|l| {
                l.members()
                    .iter()
                    .map(|(id, d)| DeviceEntry {
                        id: hex(&id.0),
                        name: d.name.clone(),
                        platform: d.platform,
                        me: *id == me,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Scans a PC's QR code and pairs (§5). Returns the PC's device id.
    async fn pair_scan_impl(
        &self,
        qr_text: String,
        ui: Arc<dyn PairConfirm>,
    ) -> Result<String, WarpError> {
        let qr = QrPayload::parse(qr_text.trim()).map_err(|_| WarpError::Invalid)?;
        let (ep, _lease) = self.mgr.acquire().await?;
        let mut dev = self.dev.lock().await;
        let client = &self.client;
        let paired = net::pair::scan(
            &ep,
            &qr,
            &dev,
            now_ms(),
            |s| async move {
                let ui = Arc::clone(&ui);
                tokio::task::spawn_blocking(move || {
                    ui.confirm(s.sas, s.device.name, s.device.platform)
                })
                .await
                .unwrap_or(false)
            },
            |records| async move { net::server::submit(client, &records).await.map(|_| ()) },
        )
        .await?;
        dev.log = Some(paired.log);
        self.save(&dev).await?;
        Ok(hex(&paired.peer.0))
    }

    /// Registers the FCM token for wakes (§6.2).
    async fn register_push_token_impl(&self, token: String) -> Result<(), WarpError> {
        let gid = self
            .dev
            .lock()
            .await
            .group_id()
            .ok_or(WarpError::NotPaired)?;
        self.client
            .put_push_token(&gid, &token)
            .await
            .map_err(|e| WarpError::Server {
                code: e.to_string(),
            })
    }

    /// Handles an FCM data message's `env` (base64url). For `connect` it dials the
    /// sender and saves items into `inbox_dir` (Kotlin then publishes them).
    async fn handle_wake_impl(
        &self,
        envelope_b64u: String,
        inbox_dir: String,
    ) -> Result<Vec<ReceivedItem>, WarpError> {
        let env = b64u::decode(&envelope_b64u).ok_or(WarpError::Invalid)?;
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
                    self.pull_log().await?;
                    synced = true;
                }
                Err(_) => return Err(WarpError::Rejected),
            }
        };
        match action {
            WakeAction::GroupChanged => {
                self.pull_log().await?;
                Ok(vec![])
            }
            WakeAction::Connect { session, dial, .. } => {
                let (ep, _lease) = self.mgr.acquire().await?;
                let log = self
                    .dev
                    .lock()
                    .await
                    .log
                    .clone()
                    .ok_or(WarpError::NotPaired)?;
                let s = flow::answer_connect(&ep, &log, &sender, session, &dial).await?;
                let policy = Policy {
                    dir: PathBuf::from(inbox_dir),
                    max_size: 500 << 20,
                    accept_large: false,
                };
                let items = s.receive(&policy, |_| true).await?;
                Ok(items
                    .into_iter()
                    .map(|r| ReceivedItem {
                        id: r.item.id,
                        kind: r.item.kind,
                        name: r.item.name,
                        mime: r.item.mime,
                        size: r.item.size,
                        path: r.path.map(|p| p.display().to_string()),
                        text: r.item.text,
                    })
                    .collect())
            }
        }
    }

    /// Sends text to a device: wake it, then wait for it to dial in (§7.4).
    async fn send_text_impl(&self, target: String, text: String) -> Result<(), WarpError> {
        let item = nx::text_item(1, &text, now_ms())?;
        self.send(target, vec![item]).await
    }

    /// Sends files (from the share sheet, copied to app storage by Kotlin).
    async fn send_files_impl(
        &self,
        target: String,
        files: Vec<OutgoingFile>,
    ) -> Result<(), WarpError> {
        let mut items = Vec::with_capacity(files.len());
        for (i, f) in files.iter().enumerate() {
            let id = u32::try_from(i)
                .map_err(|_| WarpError::Invalid)?
                .saturating_add(1);
            items.push(nx::file_item(id, std::path::Path::new(&f.path), now_ms())?);
        }
        self.send(target, items).await
    }

    /// Fetches membership changes from the server.
    async fn sync_impl(&self) -> Result<(), WarpError> {
        self.pull_log().await
    }
}

impl Warpshot {
    async fn send(&self, target: String, items: Vec<OutItem>) -> Result<(), WarpError> {
        let target = parse_id(&target)?;
        if items.iter().any(|o| matches!(o.source, Source::Bytes(_))) {
            return Err(WarpError::Invalid);
        }
        let (ep, _lease) = self.mgr.acquire().await?;
        let (env, gid, log) = {
            let dev = self.dev.lock().await;
            let gid = dev.group_id().ok_or(WarpError::NotPaired)?;
            let session = self.pending.lock().await.insert(target, items.clone())?;
            (
                flow::connect_wake(&ep, &dev, &target, session, &items, now_ms())?,
                gid,
                dev.log.clone().ok_or(WarpError::NotPaired)?,
            )
        };
        let via = self
            .client
            .wake(&gid, &target, &env, 60)
            .await
            .map_err(|e| WarpError::Server {
                code: e.to_string(),
            })?;
        if via == warpshot_core::client::Via::None {
            return Err(WarpError::Offline);
        }
        // Wait for the woken device to dial in with our session.
        let deadline = tokio::time::Instant::now()
            .checked_add(flow::PENDING_TTL)
            .ok_or(WarpError::Invalid)?;
        loop {
            let inc = tokio::time::timeout_at(deadline, ep.accept())
                .await
                .map_err(|_| WarpError::Offline)?
                .ok_or(WarpError::Offline)?;
            let Ok(acc) = inc.accept() else { continue };
            let Ok(conn) = acc.await else { continue };
            if conn.alpn() != warpshot_core::xfer::ALPN {
                net::close(&conn, warpshot_core::xfer::code::PROTOCOL);
                continue;
            }
            let s = nx::accept(&ep, conn, &log).await?;
            let Some(p) = self.pending.lock().await.take(&s.hello_session, &s.peer) else {
                net::close(&s.conn, warpshot_core::xfer::code::PROTOCOL);
                continue;
            };
            let results = tokio::time::timeout(Duration::from_secs(3600), s.send_items(p.items))
                .await
                .map_err(|_| WarpError::Network {
                    code: warpshot_core::xfer::code::TIMEOUT,
                })??;
            return if results.iter().all(|(_, ok)| *ok) {
                Ok(())
            } else {
                Err(WarpError::Rejected)
            };
        }
    }
}

//! Named-pipe JSON-lines client for the agent IPC (docs/ipc.md).
//!
//! One connection per UI process. Requests carry a fresh `id`; the reader task
//! routes responses to the waiting caller and forwards events to the webview
//! as the Tauri event `agent-event` (`{event, data}`). Connection changes are
//! emitted as `agent-connection` (bool).

use std::collections::HashMap;
use std::os::windows::io::AsRawHandle;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use serde::Serialize;
use serde_json::{Map, Value};
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tokio::sync::{Mutex, oneshot};

/// docs/ipc.md: at most 1 MiB per line.
const MAX_LINE: usize = 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_PIPE_BUSY: i32 = 231;

/// Methods the UI may call (docs/ipc.md "Methods"). Anything else is refused
/// locally before it reaches the agent.
const METHODS: &[&str] = &[
    "status",
    "devices.list",
    "devices.rename",
    "devices.remove",
    "devices.set_default",
    "pair.start",
    "pair.confirm",
    "pair.cancel",
    "settings.get",
    "settings.set",
    "hotkey.check",
    "history.list",
    "history.reveal",
    "history.delete",
    "send.files",
    "send.text",
    "group.not_me",
    "debug.counters",
];

/// Error returned to the frontend. Codes from the agent pass through; local
/// codes: `agent-not-running`, `agent-untrusted`, `agent-disconnected`,
/// `timeout`, `unknown-method`, `bad-response`, `io`.
#[derive(Debug, Clone, Serialize)]
pub struct RpcError {
    pub code: String,
    pub message: String,
}

impl RpcError {
    fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.to_owned(),
            message: message.to_owned(),
        }
    }
}

type Reply = Result<Value, RpcError>;
type Pending = Arc<StdMutex<HashMap<u64, oneshot::Sender<Reply>>>>;

#[derive(Debug)]
struct Conn {
    writer: Arc<Mutex<WriteHalf<NamedPipeClient>>>,
    pending: Pending,
    alive: Arc<AtomicBool>,
}

#[derive(Debug)]
pub struct Agent {
    app: AppHandle,
    pipe_name: String,
    conn: Mutex<Option<Conn>>,
    next_id: AtomicU64,
}

impl Agent {
    pub fn new(app: AppHandle, sid: &str) -> Self {
        Self {
            app,
            pipe_name: pipe_name(sid, std::env::var("WARPSHOT_PIPE_SUFFIX").ok().as_deref()),
            conn: Mutex::new(None),
            next_id: AtomicU64::new(1),
        }
    }

    async fn open(&self) -> Result<NamedPipeClient, RpcError> {
        let mut busy_retries = 0u32;
        loop {
            match ClientOptions::new().open(&self.pipe_name) {
                Ok(c) => return Ok(c),
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && busy_retries < 10 => {
                    busy_retries += 1;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) => {
                    return Err(RpcError::new("agent-not-running", "pipe not found"));
                }
                Err(_) => return Err(RpcError::new("agent-not-running", "pipe open failed")),
            }
        }
    }

    /// Returns a live connection, connecting if needed.
    async fn ensure(&self) -> Result<(Arc<Mutex<WriteHalf<NamedPipeClient>>>, Pending), RpcError> {
        let mut guard = self.conn.lock().await;
        if let Some(c) = guard.as_ref()
            && c.alive.load(Ordering::Acquire)
        {
            return Ok((c.writer.clone(), c.pending.clone()));
        }
        let client = self.open().await?;
        if !crate::win::pipe_server_is_current_user(client.as_raw_handle()) {
            return Err(RpcError::new(
                "agent-untrusted",
                "pipe server is not this user",
            ));
        }
        let (rd, wr) = tokio::io::split(client);
        let conn = Conn {
            writer: Arc::new(Mutex::new(wr)),
            pending: Arc::new(StdMutex::new(HashMap::new())),
            alive: Arc::new(AtomicBool::new(true)),
        };
        let out = (conn.writer.clone(), conn.pending.clone());
        tauri::async_runtime::spawn(read_loop(
            self.app.clone(),
            rd,
            conn.pending.clone(),
            conn.alive.clone(),
        ));
        *guard = Some(conn);
        let _ = self.app.emit("agent-connection", true);
        Ok(out)
    }

    pub async fn call(&self, method: &str, params: Option<Value>) -> Reply {
        if !METHODS.contains(&method) {
            return Err(RpcError::new("unknown-method", "not allowed by the UI"));
        }
        let (writer, pending) = self.ensure().await?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut req = Map::new();
        // `jsonrpc` is not required by docs/ipc.md; unknown fields are ignored
        // there, and it keeps the client compatible with JSON-RPC 2.0 servers.
        req.insert("jsonrpc".into(), Value::from("2.0"));
        req.insert("id".into(), Value::from(id));
        req.insert("method".into(), Value::from(method));
        if let Some(p) = params {
            req.insert("params".into(), p);
        }
        let mut line = serde_json::to_vec(&Value::Object(req))
            .map_err(|_| RpcError::new("bad-params", "encode failed"))?;
        if line.len() >= MAX_LINE {
            return Err(RpcError::new("bad-params", "request too large"));
        }
        line.push(b'\n');

        let (tx, rx) = oneshot::channel();
        if let Ok(mut p) = pending.lock() {
            p.insert(id, tx);
        }
        let write_res = {
            let mut w = writer.lock().await;
            match w.write_all(&line).await {
                Ok(()) => w.flush().await,
                Err(e) => Err(e),
            }
        };
        if write_res.is_err() {
            if let Ok(mut p) = pending.lock() {
                p.remove(&id);
            }
            return Err(RpcError::new("agent-disconnected", "write failed"));
        }
        match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(reply)) => reply,
            Ok(Err(_)) => Err(RpcError::new("agent-disconnected", "connection closed")),
            Err(_) => {
                if let Ok(mut p) = pending.lock() {
                    p.remove(&id);
                }
                Err(RpcError::new("timeout", "no response"))
            }
        }
    }
}

/// Reads one `\n`-terminated line of at most `MAX_LINE` bytes into `buf`.
/// `Ok(false)` on clean EOF.
async fn read_line_limited(
    r: &mut BufReader<ReadHalf<NamedPipeClient>>,
    buf: &mut Vec<u8>,
) -> std::io::Result<bool> {
    buf.clear();
    loop {
        let chunk = r.fill_buf().await?;
        if chunk.is_empty() {
            return Ok(false);
        }
        let (take, done) = match chunk.iter().position(|&b| b == b'\n') {
            Some(i) => (i.saturating_add(1), true),
            None => (chunk.len(), false),
        };
        let part = chunk.get(..take).unwrap_or_default();
        if buf.len().saturating_add(part.len()) > MAX_LINE.saturating_add(1) {
            return Err(std::io::Error::other("line too long"));
        }
        buf.extend_from_slice(part);
        r.consume(take);
        if done {
            buf.pop();
            return Ok(true);
        }
    }
}

fn agent_error(v: &Value) -> RpcError {
    let code = match v.get("code") {
        Some(Value::String(s)) if s.len() <= 64 => s.clone(),
        Some(Value::Number(n)) => n.to_string(), // JSON-RPC 2.0 style numeric codes
        _ => "error".to_owned(),
    };
    let message: String = v
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("")
        .chars()
        .take(200)
        .collect();
    RpcError { code, message }
}

/// `\\.\pipe\warpshot-<SID>`. `WARPSHOT_PIPE_SUFFIX` (1-32 chars of
/// `[a-z0-9]`) selects `warpshot-<SID>-<suffix>` so the dev mock agent can run
/// beside a real agent; anything else is ignored. The server-owner check
/// applies either way.
fn pipe_name(sid: &str, suffix: Option<&str>) -> String {
    match suffix {
        Some(s)
            if (1..=32).contains(&s.len())
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) =>
        {
            format!(r"\\.\pipe\warpshot-{sid}-{s}")
        }
        _ => format!(r"\\.\pipe\warpshot-{sid}"),
    }
}

async fn read_loop(
    app: AppHandle,
    rd: ReadHalf<NamedPipeClient>,
    pending: Pending,
    alive: Arc<AtomicBool>,
) {
    let mut reader = BufReader::with_capacity(64 * 1024, rd);
    let mut buf = Vec::new();
    while let Ok(true) = read_line_limited(&mut reader, &mut buf).await {
        let Ok(Value::Object(msg)) = serde_json::from_slice::<Value>(&buf) else {
            continue; // not a JSON object: ignore the line
        };
        if let Some(id) = msg.get("id").and_then(Value::as_u64) {
            let reply = if let Some(err) = msg.get("error") {
                Err(agent_error(err))
            } else if let Some(res) = msg.get("result") {
                Ok(res.clone())
            } else {
                Err(RpcError::new("bad-response", "no result"))
            };
            let tx = pending.lock().ok().and_then(|mut p| p.remove(&id));
            if let Some(tx) = tx {
                let _ = tx.send(reply);
            }
        } else if let Some(name) = msg.get("event").and_then(Value::as_str) {
            let data = msg.get("data").cloned().unwrap_or(Value::Null);
            let _ = app.emit(
                "agent-event",
                serde_json::json!({ "event": name, "data": data }),
            );
        }
    }
    alive.store(false, Ordering::Release);
    if let Ok(mut p) = pending.lock() {
        for (_, tx) in p.drain() {
            let _ = tx.send(Err(RpcError::new(
                "agent-disconnected",
                "connection closed",
            )));
        }
    }
    let _ = app.emit("agent-connection", false);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_names() {
        assert_eq!(
            pipe_name("S-1-5-21-1", None),
            r"\\.\pipe\warpshot-S-1-5-21-1"
        );
        assert_eq!(
            pipe_name("S-1-5-21-1", Some("dev")),
            r"\\.\pipe\warpshot-S-1-5-21-1-dev"
        );
        let long = "a".repeat(33);
        for bad in ["", "Dev", "a/b", "..", "x y", r"a\b", long.as_str()] {
            assert_eq!(
                pipe_name("S-1", Some(bad)),
                r"\\.\pipe\warpshot-S-1",
                "{bad:?}"
            );
        }
    }

    #[test]
    fn error_codes() {
        let e = agent_error(&serde_json::json!({"code": "bad-params", "message": "m"}));
        assert_eq!((e.code.as_str(), e.message.as_str()), ("bad-params", "m"));
        let e = agent_error(&serde_json::json!({"code": -32601, "message": "x"}));
        assert_eq!(e.code, "-32601");
        let e = agent_error(&serde_json::json!({"code": [1]}));
        assert_eq!(e.code, "error");
    }
}

//! Named-pipe IPC (docs/ipc.md: one JSON object per line; requests, responses
//! and unsolicited events) between the agent and `warpshot-ui`: `\\.\pipe\warpshot-<user SID>`.
//!
//! Threat model T9: the pipe's DACL grants access only to the current user SID
//! (protected, so nothing is inherited), the owner is set to that SID, remote
//! clients are rejected (`PIPE_REJECT_REMOTE_CLIENTS`), and the first instance is
//! created with `FILE_FLAG_FIRST_PIPE_INSTANCE` so a pre-created (squatted) pipe
//! makes the agent fail instead of serving on someone else's object. The client
//! checks that the pipe is owned by its own user SID before sending anything.
//!
//! Runs on the agent's single tokio `current_thread` runtime; pipe I/O uses that
//! thread's IOCP, so no extra threads. Lines are capped at [`MAX_MESSAGE`] bytes
//! and at most [`MAX_CLIENTS`] connections are served at once.

use std::{
    fmt,
    future::Future,
    io,
    os::windows::io::AsRawHandle,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions},
    sync::broadcast,
};
use windows_sys::Win32::{
    Foundation::{ERROR_PIPE_BUSY, ERROR_SUCCESS},
    Security::{
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
            SE_KERNEL_OBJECT,
        },
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    },
};

use crate::win::{LocalBox, current_user_sid, last_error, sid_to_string, wide};

/// Longest request or response line (bytes, without the newline).
pub const MAX_MESSAGE: usize = 1024 * 1024;
/// Most concurrent client connections; extra ones are closed right away.
pub const MAX_CLIENTS: usize = 8;
const PIPE_BUFFER: u32 = 4096;

/// Error codes (docs/ipc.md).
pub mod code {
    pub const PARSE_ERROR: &str = "parse-error";
    pub const INVALID_REQUEST: &str = "bad-request";
    pub const METHOD_NOT_FOUND: &str = "unknown-method";
    pub const INVALID_PARAMS: &str = "bad-params";
    pub const INTERNAL_ERROR: &str = "internal";
}

/// The agent's pipe name for the current user.
pub fn pipe_name() -> io::Result<String> {
    Ok(format!(r"\\.\pipe\warpshot-{}", current_user_sid()?))
}

/// An error object: `{code, message}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcError {
    pub code: String,
    /// Short, content-free message (error codes, not data).
    pub message: String,
}

impl RpcError {
    pub fn new(code: &str, message: &str) -> RpcError {
        RpcError {
            code: code.to_string(),
            message: message.to_string(),
        }
    }

    pub fn method_not_found() -> RpcError {
        RpcError::new(code::METHOD_NOT_FOUND, "method not found")
    }
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rpc error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for RpcError {}

/// Handles one request. Notifications (no `id`) are handled too; their result is dropped.
pub trait Handler: Send + Sync + 'static {
    fn call(
        &self,
        method: &str,
        params: Value,
    ) -> impl Future<Output = Result<Value, RpcError>> + Send;
}

/// A self-relative security descriptor from `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
struct SecDesc(LocalBox);

// SAFETY: the descriptor is immutable after creation and only read by the OS;
// sharing or moving the pointer between threads is sound.
unsafe impl Send for SecDesc {}
// SAFETY: as above.
unsafe impl Sync for SecDesc {}

impl SecDesc {
    /// Owner = user, DACL protected with a single "generic all" ACE for the user.
    fn user_only(sid: &str) -> io::Result<SecDesc> {
        let sddl = wide(&format!("O:{sid}D:P(A;;GA;;;{sid})"));
        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: valid SDDL string; `psd` receives a LocalAlloc'd descriptor we own.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut psd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_error());
        }
        Ok(SecDesc(LocalBox(psd)))
    }
}

/// A bound pipe: the first instance exists, ready for [`PipeServer::serve`].
pub struct PipeServer {
    name: String,
    sd: SecDesc,
    first: NamedPipeServer,
}

impl fmt::Debug for PipeServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PipeServer")
            .field("name", &self.name)
            .finish()
    }
}

fn create_instance(name: &str, sd: &SecDesc, first: bool) -> io::Result<NamedPipeServer> {
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: sd.0.0,
        bInheritHandle: 0,
    };
    let mut opts = ServerOptions::new();
    opts.first_pipe_instance(first)
        .reject_remote_clients(true)
        .in_buffer_size(PIPE_BUFFER)
        .out_buffer_size(PIPE_BUFFER);
    // SAFETY: `sa` is a valid SECURITY_ATTRIBUTES whose descriptor (owned by `sd`)
    // outlives the call; CreateNamedPipeW copies it.
    unsafe { opts.create_with_security_attributes_raw(name, (&raw mut sa).cast()) }
}

impl PipeServer {
    /// Creates the first pipe instance. Fails if the name already exists (another
    /// agent, or a squatter). Must be called inside the tokio runtime.
    pub fn bind(name: &str) -> io::Result<PipeServer> {
        let sd = SecDesc::user_only(&current_user_sid()?)?;
        let first = create_instance(name, &sd, true)?;
        Ok(PipeServer {
            name: name.to_string(),
            sd,
            first,
        })
    }

    /// Accepts clients forever, one task per connection. Every client receives
    /// the values sent on `events` as event lines.
    pub async fn serve<H: Handler>(
        self,
        handler: Arc<H>,
        events: broadcast::Sender<Value>,
    ) -> io::Result<()> {
        let PipeServer { name, sd, first } = self;
        let active = Arc::new(AtomicUsize::new(0));
        let mut next = first;
        loop {
            let connected = next.connect().await;
            let pipe = std::mem::replace(&mut next, create_instance(&name, &sd, false)?);
            if connected.is_err() {
                continue; // client went away during connect; `pipe` is dropped
            }
            if active.fetch_add(1, Ordering::AcqRel) >= MAX_CLIENTS {
                active.fetch_sub(1, Ordering::AcqRel);
                continue; // over the limit: drop (disconnect) this client
            }
            let guard = ActiveGuard(Arc::clone(&active));
            let h = Arc::clone(&handler);
            let ev = events.subscribe();
            tokio::spawn(async move {
                let _guard = guard;
                let _ = serve_connection(pipe, h, ev).await;
            });
        }
    }
}

struct ActiveGuard(Arc<AtomicUsize>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        // The last client left: the UI session was work, release its pages
        // (resource-budget.md §2.7).
        if self.0.fetch_sub(1, Ordering::AcqRel) == 1 {
            crate::power::trim_working_set();
        }
    }
}

/// Reads one `\n`-terminated line of at most [`MAX_MESSAGE`] bytes.
/// `Ok(None)` on clean EOF; an error for oversize or truncated lines.
async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
) -> io::Result<Option<()>> {
    buf.clear();
    let limit = u64::try_from(MAX_MESSAGE)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let n = (&mut *r).take(limit).read_until(b'\n', buf).await?;
    if n == 0 {
        return Ok(None);
    }
    if buf.last() != Some(&b'\n') {
        let kind = if buf.len() > MAX_MESSAGE {
            "message too large"
        } else {
            "truncated message"
        };
        return Err(io::Error::new(io::ErrorKind::InvalidData, kind));
    }
    buf.pop();
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    Ok(Some(()))
}

async fn serve_connection<H: Handler>(
    pipe: NamedPipeServer,
    h: Arc<H>,
    mut events: broadcast::Receiver<Value>,
) -> io::Result<()> {
    let (rd, mut wr) = tokio::io::split(pipe);
    let mut io = BufReader::with_capacity(4096, rd);
    let mut line = Vec::new();
    loop {
        let mut out = tokio::select! {
            r = read_line(&mut io, &mut line) => {
                if r?.is_none() {
                    return Ok(());
                }
                if line.is_empty() {
                    continue;
                }
                let Some(resp) = dispatch(&*h, &line).await else { continue };
                let out = serde_json::to_vec(&resp).map_err(io::Error::other)?;
                if out.len() > MAX_MESSAGE {
                    let id = resp.get("id").cloned().unwrap_or(Value::Null);
                    serde_json::to_vec(&error_response(
                        id,
                        &RpcError::new(code::INTERNAL_ERROR, "response too large"),
                    ))
                    .map_err(io::Error::other)?
                } else {
                    out
                }
            }
            ev = events.recv() => match ev {
                Ok(v) => serde_json::to_vec(&v).map_err(io::Error::other)?,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return Ok(()),
            },
        };
        out.push(b'\n');
        wr.write_all(&out).await?;
    }
}

fn error_response(id: Value, e: &RpcError) -> Value {
    json!({ "id": id, "error": { "code": e.code, "message": e.message } })
}

/// Parses one request line and runs it. `None` for notifications.
pub async fn dispatch<H: Handler>(h: &H, line: &[u8]) -> Option<Value> {
    let Ok(req) = serde_json::from_slice::<Value>(line) else {
        return Some(error_response(
            Value::Null,
            &RpcError::new(code::PARSE_ERROR, "parse error"),
        ));
    };
    let id = req.get("id").cloned();
    let valid_id = matches!(
        id,
        None | Some(Value::Null | Value::Number(_) | Value::String(_))
    );
    let method = req.get("method").and_then(Value::as_str);
    // `jsonrpc` is optional (docs/ipc.md); JSON-RPC clients may still send "2.0".
    let version_ok = req.get("jsonrpc").is_none_or(|v| v.as_str() == Some("2.0"));
    let (Some(method), true, true) = (method, valid_id, version_ok) else {
        let id = if valid_id {
            id.unwrap_or(Value::Null)
        } else {
            Value::Null
        };
        return Some(error_response(
            id,
            &RpcError::new(code::INVALID_REQUEST, "invalid request"),
        ));
    };
    let params = req.get("params").cloned().unwrap_or(Value::Null);
    let result = h.call(method, params).await;
    let id = id?; // notification: no response
    Some(match result {
        Ok(v) => json!({ "id": id, "result": v }),
        Err(e) => error_response(id, &e),
    })
}

#[derive(Debug)]
pub enum ClientError {
    Io(io::Error),
    /// The pipe is not owned by our user SID (possible squatter).
    WrongOwner,
    Rpc(RpcError),
    Protocol(&'static str),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Io(e) => write!(f, "pipe: {e}"),
            ClientError::WrongOwner => f.write_str("pipe is not owned by the current user"),
            ClientError::Rpc(e) => write!(f, "{e}"),
            ClientError::Protocol(m) => write!(f, "protocol: {m}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        ClientError::Io(e)
    }
}

/// Owner SID (string form) of a kernel object handle.
fn owner_sid(handle: std::os::windows::io::RawHandle) -> io::Result<String> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: valid handle opened with READ_CONTROL (GENERIC_READ); out-pointers are
    // locals; `psd` is LocalAlloc'd and owns the memory `owner` points into.
    let rc = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut psd,
        )
    };
    let _sd = LocalBox(psd);
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(rc).unwrap_or(i32::MAX),
        ));
    }
    // SAFETY: `owner` points into `psd`, alive until `_sd` drops at the end of scope.
    unsafe { sid_to_string(owner) }
}

/// A client for the agent pipe (used by tests, tools and later the UI).
#[derive(Debug)]
pub struct PipeClient {
    io: BufReader<NamedPipeClient>,
    next_id: u64,
}

impl PipeClient {
    /// Connects (retrying briefly while all instances are busy) and verifies the
    /// pipe owner is the current user.
    pub async fn connect(name: &str) -> Result<PipeClient, ClientError> {
        let mut attempts = 0u32;
        let pipe = loop {
            match ClientOptions::new().open(name) {
                Ok(p) => break p,
                Err(e)
                    if e.raw_os_error() == i32::try_from(ERROR_PIPE_BUSY).ok() && attempts < 20 =>
                {
                    attempts = attempts.saturating_add(1);
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Err(e) => return Err(e.into()),
            }
        };
        if owner_sid(pipe.as_raw_handle())? != current_user_sid()? {
            return Err(ClientError::WrongOwner);
        }
        Ok(PipeClient {
            io: BufReader::with_capacity(4096, pipe),
            next_id: 1,
        })
    }

    /// Sends a request and waits for its response.
    pub async fn call(&mut self, method: &str, params: Value) -> Result<Value, ClientError> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let req = json!({ "id": id, "method": method, "params": params });
        let mut out = serde_json::to_vec(&req).map_err(io::Error::other)?;
        if out.len() > MAX_MESSAGE {
            return Err(ClientError::Protocol("request too large"));
        }
        out.push(b'\n');
        self.io.get_mut().write_all(&out).await?;
        let mut line = Vec::new();
        let resp = loop {
            if read_line(&mut self.io, &mut line).await?.is_none() {
                return Err(ClientError::Protocol("connection closed"));
            }
            let v: Value =
                serde_json::from_slice(&line).map_err(|_| ClientError::Protocol("invalid json"))?;
            if v.get("event").is_none() {
                break v; // this simple client skips events
            }
        };
        if resp.get("id").and_then(Value::as_u64) != Some(id) {
            return Err(ClientError::Protocol("unexpected id"));
        }
        if let Some(err) = resp.get("error") {
            let code = err
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or(code::INTERNAL_ERROR);
            let message = err.get("message").and_then(Value::as_str).unwrap_or("");
            return Err(ClientError::Rpc(RpcError::new(code, message)));
        }
        resp.get("result")
            .cloned()
            .ok_or(ClientError::Protocol("missing result"))
    }

    /// Sends a raw line (tests: malformed input).
    #[cfg(test)]
    async fn send_raw(&mut self, line: &[u8]) -> io::Result<Option<Value>> {
        self.io.get_mut().write_all(line).await?;
        let mut buf = Vec::new();
        Ok(match read_line(&mut self.io, &mut buf).await {
            Ok(Some(())) => serde_json::from_slice(&buf).ok(),
            _ => None,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    struct Echo;

    impl Handler for Echo {
        async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
            match method {
                "echo" => Ok(params),
                "ping" => Ok(json!("pong")),
                _ => Err(RpcError::method_not_found()),
            }
        }
    }

    fn test_name(tag: &str) -> String {
        format!(
            r"\\.\pipe\warpshot-test-{}-{}-{tag}",
            current_user_sid().unwrap(),
            std::process::id()
        )
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap()
    }

    #[test]
    fn round_trip_on_local_pipe() {
        rt().block_on(async {
            let name = test_name("rt");
            let server = PipeServer::bind(&name).unwrap();
            let (ev, _) = broadcast::channel(4);
            tokio::spawn(server.serve(Arc::new(Echo), ev.clone()));
            let mut c = PipeClient::connect(&name).await.unwrap();
            let v = json!({"a": [1, 2, 3], "s": "ğüş"});
            assert_eq!(c.call("echo", v.clone()).await.unwrap(), v);
            assert_eq!(c.call("ping", Value::Null).await.unwrap(), json!("pong"));
            match c.call("nope", Value::Null).await {
                Err(ClientError::Rpc(e)) => assert_eq!(e.code, code::METHOD_NOT_FOUND),
                other => panic!("{other:?}"),
            }
            // A second concurrent client works too.
            let mut c2 = PipeClient::connect(&name).await.unwrap();
            assert_eq!(c2.call("ping", Value::Null).await.unwrap(), json!("pong"));
            // Events reach connected clients as event lines.
            ev.send(json!({"event": "status", "data": {}})).unwrap();
            let r = c2
                .send_raw(b"{\"id\":9,\"method\":\"ping\"}\n")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(r["event"], "status");
        });
    }

    #[test]
    fn malformed_and_oversize_requests() {
        rt().block_on(async {
            let name = test_name("bad");
            tokio::spawn(
                PipeServer::bind(&name)
                    .unwrap()
                    .serve(Arc::new(Echo), broadcast::channel(4).0),
            );
            let mut c = PipeClient::connect(&name).await.unwrap();
            let r = c.send_raw(b"{not json\n").await.unwrap().unwrap();
            assert_eq!(r["error"]["code"], code::PARSE_ERROR);
            let r = c
                .send_raw(b"{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"ping\"}\n")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(r["error"]["code"], code::INVALID_REQUEST);
            assert_eq!(r["id"], 1);
            let r = c
                .send_raw(b"{\"id\":[1],\"method\":\"ping\"}\n")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(r["error"]["code"], code::INVALID_REQUEST);
            assert_eq!(r["id"], Value::Null);
            let r = c
                .send_raw(b"{\"id\":2,\"method\":5}\n")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(r["error"]["code"], code::INVALID_REQUEST);
            // Notification: no response; the next call still works.
            c.io.get_mut()
                .write_all(b"{\"method\":\"ping\"}\n")
                .await
                .unwrap();
            assert_eq!(c.call("ping", Value::Null).await.unwrap(), json!("pong"));
            // Oversize line: the server closes the connection without answering.
            let mut big = vec![b'x'; MAX_MESSAGE + 10];
            big.push(b'\n');
            assert!(c.send_raw(&big).await.ok().flatten().is_none());
            // The server keeps serving new clients.
            let mut c2 = PipeClient::connect(&name).await.unwrap();
            assert_eq!(c2.call("ping", Value::Null).await.unwrap(), json!("pong"));
        });
    }

    #[test]
    fn second_bind_is_refused() {
        rt().block_on(async {
            let name = test_name("dup");
            let _first = PipeServer::bind(&name).unwrap();
            assert!(
                PipeServer::bind(&name).is_err(),
                "FILE_FLAG_FIRST_PIPE_INSTANCE must refuse"
            );
        });
    }

    #[test]
    fn pipe_owner_is_current_user() {
        rt().block_on(async {
            let name = test_name("own");
            let server = PipeServer::bind(&name).unwrap();
            assert_eq!(
                owner_sid(server.first.as_raw_handle()).unwrap(),
                current_user_sid().unwrap()
            );
        });
    }

    #[test]
    fn name_contains_sid() {
        assert!(
            pipe_name()
                .unwrap()
                .starts_with(r"\\.\pipe\warpshot-S-1-5-")
        );
    }
}

//! Typed REST API (protocol §6.2). Responses are parsed strictly; records are
//! returned as raw bytes for the caller to validate with [`crate::log::Log`]
//! (the server's view is never trusted for security decisions).

use super::{
    Client, ClientError, ErrorCode, MAX_RESPONSE, gid_segment,
    http::{self, Response},
    json::{self, Value},
    parse_head,
};
use crate::{
    b64u,
    keys::EndpointId,
    log::{self, GroupId, Head, MAX_MEMBERS, MAX_RECORD, MAX_RECORDS},
    wake::MAX_ENVELOPE_B64U,
};

/// Cap for `GET …/log`: the endpoint is not paginated, so a full log of
/// [`MAX_RECORDS`] records of [`MAX_RECORD`] bytes must fit (about 5.5 MiB).
pub const MAX_LOG_RESPONSE: usize = MAX_RECORDS * (MAX_RECORD * 4 / 3 + 4) + 4096;
/// Largest accepted `ttl` (seconds) for a wake (§6.5 uses 60 and 86400).
pub const MAX_WAKE_TTL: u32 = 86_400;
/// Largest push token accepted locally (the server caps it at 1024).
pub const MAX_PUSH_TOKEN: usize = 1024;

/// Wake routing result (§6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Ws,
    Push,
    None,
}

impl Via {
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s {
            "ws" => Some(Self::Ws),
            "push" => Some(Self::Push),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

/// One `devices` entry of the presence response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePresence {
    pub id: EndpointId,
    pub online: bool,
    pub push: bool,
    /// ms, 60 s granularity; `None` if never seen.
    pub last_seen: Option<u64>,
}

/// `GET …/log` result: raw `SignedRecord`s after `after`, and the server's head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogPage {
    pub records: Vec<Vec<u8>>,
    pub head: Head,
}

/// `append` failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendError {
    /// 409 `head-moved`: the server's head differs from the record's `prev`.
    HeadMoved(Head),
    Client(ClientError),
}

impl From<ClientError> for AppendError {
    fn from(e: ClientError) -> Self {
        Self::Client(e)
    }
}

impl std::fmt::Display for AppendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeadMoved(h) => write!(f, "head-moved (seq {})", h.seq),
            Self::Client(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for AppendError {}

pub(crate) fn parse_body(r: &Response) -> Result<Value, ClientError> {
    json::parse(&r.body).map_err(|_| ClientError::Malformed)
}

/// The §6.8 error of a non-success response.
pub(crate) fn server_error(r: &Response) -> ClientError {
    let code = parse_body(r)
        .ok()
        .and_then(|v| v.get("error").and_then(Value::as_str).map(ErrorCode::parse))
        .unwrap_or(ErrorCode::Unknown);
    ClientError::Server {
        status: r.status,
        code,
    }
}

fn expect_status(r: &Response, status: u16) -> Result<(), ClientError> {
    if r.status == status {
        Ok(())
    } else {
        Err(server_error(r))
    }
}

pub(crate) fn parse_records(v: Option<&Value>) -> Result<Vec<Vec<u8>>, ClientError> {
    let arr = v.and_then(Value::as_array).ok_or(ClientError::Malformed)?;
    if arr.len() > MAX_RECORDS {
        return Err(ClientError::Malformed);
    }
    arr.iter()
        .map(|r| {
            r.as_str()
                .and_then(b64u::decode)
                .filter(|b| !b.is_empty() && b.len() <= MAX_RECORD)
                .ok_or(ClientError::Malformed)
        })
        .collect()
}

pub(crate) fn parse_devices(v: Option<&Value>) -> Result<Vec<DevicePresence>, ClientError> {
    let arr = v.and_then(Value::as_array).ok_or(ClientError::Malformed)?;
    if arr.len() > MAX_MEMBERS {
        return Err(ClientError::Malformed);
    }
    arr.iter()
        .map(|d| {
            let id = d
                .get("id")
                .and_then(Value::as_str)
                .and_then(b64u::decode)
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or(ClientError::Malformed)?;
            let online = d.get("online").and_then(Value::as_bool);
            let push = d.get("push").and_then(Value::as_bool);
            let last_seen = match d.get("last_seen") {
                Some(Value::Null) | None => None,
                Some(v) => Some(v.as_u64().ok_or(ClientError::Malformed)?),
            };
            Ok(DevicePresence {
                id: EndpointId(id),
                online: online.ok_or(ClientError::Malformed)?,
                push: push.ok_or(ClientError::Malformed)?,
                last_seen,
            })
        })
        .collect()
}

/// Checks local wake arguments and returns `(b64u to, b64u env)`.
pub(crate) fn wake_args(
    to: &EndpointId,
    env: &[u8],
    ttl: u32,
) -> Result<(String, String), ClientError> {
    let env = b64u::encode(env);
    if env.is_empty() || env.len() > MAX_ENVELOPE_B64U || ttl == 0 || ttl > MAX_WAKE_TTL {
        return Err(ClientError::Argument);
    }
    Ok((b64u::encode(&to.0), env))
}

impl Client {
    fn group_path(gid: &GroupId, endpoint: &str) -> String {
        format!("/v1/groups/{}/{endpoint}", gid_segment(gid))
    }

    /// `POST /v1/groups` with a signed genesis record. The request is signed
    /// by this client's key, which must be the genesis signer (§6.1).
    pub async fn create_group(&self, genesis: &[u8]) -> Result<Head, ClientError> {
        let (body, ..) = log::parse_signed(genesis).map_err(|_| ClientError::Argument)?;
        let req = json::object(&[("genesis", json::str_lit(&b64u::encode(genesis)))]);
        let mut extra = Vec::new();
        if let Some(t) = &self.inner.create_token {
            extra.push(("Warpshot-Create-Token", t.as_str()));
        }
        let r = http::signed_request(
            &self.inner,
            "POST",
            "/v1/groups",
            Some(req.as_bytes()),
            &extra,
            MAX_RESPONSE,
        )
        .await?;
        expect_status(&r, 201)?;
        let v = parse_body(&r)?;
        let group = v
            .get("group")
            .and_then(Value::as_str)
            .ok_or(ClientError::Malformed)?;
        if group != gid_segment(&body.group_id) {
            return Err(ClientError::Malformed);
        }
        parse_head(v.get("head").ok_or(ClientError::Malformed)?)
    }

    /// `GET /v1/groups/{gid}/log[?after=seq]`: records with `seq > after`
    /// (all records when `after` is `None`).
    pub async fn get_log(&self, gid: &GroupId, after: Option<u64>) -> Result<LogPage, ClientError> {
        let mut target = Self::group_path(gid, "log");
        if let Some(a) = after {
            target.push_str(&format!("?after={a}"));
        }
        let r =
            http::signed_request(&self.inner, "GET", &target, None, &[], MAX_LOG_RESPONSE).await?;
        expect_status(&r, 200)?;
        let v = parse_body(&r)?;
        Ok(LogPage {
            records: parse_records(v.get("records"))?,
            head: parse_head(v.get("head").ok_or(ClientError::Malformed)?)?,
        })
    }

    /// `POST /v1/groups/{gid}/log` (compare-and-swap on the head, §4.4).
    pub async fn append(&self, gid: &GroupId, record: &[u8]) -> Result<Head, AppendError> {
        if record.is_empty() || record.len() > MAX_RECORD {
            return Err(ClientError::Argument.into());
        }
        let req = json::object(&[("record", json::str_lit(&b64u::encode(record)))]);
        let target = Self::group_path(gid, "log");
        let r = http::signed_request(
            &self.inner,
            "POST",
            &target,
            Some(req.as_bytes()),
            &[],
            MAX_RESPONSE,
        )
        .await?;
        match r.status {
            200 => {
                let v = parse_body(&r)?;
                Ok(parse_head(v.get("head").ok_or(ClientError::Malformed)?)?)
            }
            409 => {
                let v = parse_body(&r).ok();
                let moved = v.as_ref().and_then(|v| {
                    (v.get("error").and_then(Value::as_str) == Some("head-moved"))
                        .then(|| v.get("head").map(parse_head))
                        .flatten()
                });
                match moved {
                    Some(Ok(h)) => Err(AppendError::HeadMoved(h)),
                    _ => Err(server_error(&r).into()),
                }
            }
            _ => Err(server_error(&r).into()),
        }
    }

    /// `POST /v1/groups/{gid}/wake` with a sealed envelope (§7) for `to`.
    pub async fn wake(
        &self,
        gid: &GroupId,
        to: &EndpointId,
        env: &[u8],
        ttl: u32,
    ) -> Result<Via, ClientError> {
        let (to, env) = wake_args(to, env, ttl)?;
        let req = json::object(&[
            ("to", json::str_lit(&to)),
            ("env", json::str_lit(&env)),
            ("ttl", json::uint(u64::from(ttl))),
        ]);
        let target = Self::group_path(gid, "wake");
        let r = http::signed_request(
            &self.inner,
            "POST",
            &target,
            Some(req.as_bytes()),
            &[],
            MAX_RESPONSE,
        )
        .await?;
        expect_status(&r, 200)?;
        parse_body(&r)?
            .get("via")
            .and_then(Value::as_str)
            .and_then(Via::parse)
            .ok_or(ClientError::Malformed)
    }

    /// `PUT /v1/groups/{gid}/push-token` (provider `fcm`).
    pub async fn put_push_token(&self, gid: &GroupId, token: &str) -> Result<(), ClientError> {
        if token.is_empty()
            || token.len() > MAX_PUSH_TOKEN
            || !token
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b':' | b'-' | b'.'))
        {
            return Err(ClientError::Argument);
        }
        let req = zeroize::Zeroizing::new(json::object(&[
            ("provider", json::str_lit("fcm")),
            ("token", json::str_lit(token)),
        ]));
        let target = Self::group_path(gid, "push-token");
        let r = http::signed_request(
            &self.inner,
            "PUT",
            &target,
            Some(req.as_bytes()),
            &[],
            MAX_RESPONSE,
        )
        .await?;
        expect_status(&r, 204)
    }

    /// `DELETE /v1/groups/{gid}/push-token`.
    pub async fn delete_push_token(&self, gid: &GroupId) -> Result<(), ClientError> {
        let target = Self::group_path(gid, "push-token");
        let r =
            http::signed_request(&self.inner, "DELETE", &target, None, &[], MAX_RESPONSE).await?;
        expect_status(&r, 204)
    }

    /// `GET /v1/groups/{gid}/presence`.
    pub async fn presence(&self, gid: &GroupId) -> Result<Vec<DevicePresence>, ClientError> {
        let target = Self::group_path(gid, "presence");
        let r = http::signed_request(&self.inner, "GET", &target, None, &[], MAX_RESPONSE).await?;
        expect_status(&r, 200)?;
        parse_devices(parse_body(&r)?.get("devices"))
    }

    /// `GET /v1/health` (unauthenticated in the spec; signing it is harmless).
    pub async fn health(&self) -> Result<(), ClientError> {
        let r =
            http::signed_request(&self.inner, "GET", "/v1/health", None, &[], MAX_RESPONSE).await?;
        expect_status(&r, 200)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn resp(status: u16, body: &str) -> Response {
        Response {
            status,
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn error_mapping() {
        assert_eq!(
            server_error(&resp(403, r#"{"error":"not-member"}"#)),
            ClientError::Server {
                status: 403,
                code: ErrorCode::NotMember
            }
        );
        assert_eq!(
            server_error(&resp(502, "<html>")),
            ClientError::Server {
                status: 502,
                code: ErrorCode::Unknown
            }
        );
        assert_eq!(
            server_error(&resp(400, r#"{"error":7}"#)),
            ClientError::Server {
                status: 400,
                code: ErrorCode::Unknown
            }
        );
    }

    #[test]
    fn head_parsing() {
        let id = b64u::encode(&[7; 32]);
        let v = json::parse(format!(r#"{{"seq":5,"id":"{id}"}}"#).as_bytes()).unwrap();
        assert_eq!(parse_head(&v).unwrap().seq, 5);
        for bad in [
            r#"{"seq":5}"#.to_string(),
            r#"{"seq":5,"id":""}"#.to_string(),
            format!(r#"{{"seq":"5","id":"{id}"}}"#),
            format!(r#"{{"seq":5,"id":"{}"}}"#, b64u::encode(&[7; 31])),
            format!(r#"{{"seq":5,"id":"{id}="}}"#),
        ] {
            let v = json::parse(bad.as_bytes()).unwrap();
            assert!(parse_head(&v).is_err(), "{bad}");
        }
    }

    #[test]
    fn records_and_devices() {
        let v = json::parse(br#"{"r":["AAEC"],"bad":["A"],"empty":[""]}"#).unwrap();
        assert_eq!(parse_records(v.get("r")).unwrap(), vec![vec![0, 1, 2]]);
        assert!(parse_records(v.get("bad")).is_err());
        assert!(parse_records(v.get("empty")).is_err());
        assert!(parse_records(None).is_err());
        let big = format!(r#"["{}"]"#, b64u::encode(&[0; MAX_RECORD + 1]));
        assert!(parse_records(Some(&json::parse(big.as_bytes()).unwrap())).is_err());

        let id = b64u::encode(&[9; 32]);
        let ok = format!(
            r#"[{{"id":"{id}","online":true,"push":false,"last_seen":null}},{{"id":"{id}","online":false,"push":true,"last_seen":60000}}]"#
        );
        let d = parse_devices(Some(&json::parse(ok.as_bytes()).unwrap())).unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].last_seen, None);
        assert_eq!(d[1].last_seen, Some(60000));
        for bad in [
            format!(r#"[{{"id":"{id}","online":1,"push":false}}]"#),
            format!(r#"[{{"id":"{id}","push":false}}]"#),
            format!(r#"[{{"id":"{id}","online":true,"push":false,"last_seen":"x"}}]"#),
            r#"[{"id":"AA","online":true,"push":false}]"#.to_string(),
            format!("[{}]", [ok.trim_matches(['[', ']']); 9].join(",")),
        ] {
            assert!(
                parse_devices(Some(&json::parse(bad.as_bytes()).unwrap())).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn wake_argument_limits() {
        let to = EndpointId([1; 32]);
        assert!(wake_args(&to, &[0; 2850], 60).is_ok());
        assert_eq!(wake_args(&to, &[0; 2851], 60), Err(ClientError::Argument));
        assert_eq!(wake_args(&to, &[], 60), Err(ClientError::Argument));
        assert_eq!(wake_args(&to, &[1], 0), Err(ClientError::Argument));
        assert_eq!(
            wake_args(&to, &[1], MAX_WAKE_TTL + 1),
            Err(ClientError::Argument)
        );
    }
}

//! Server client (§6) against a real server. Skipped unless
//! `WARPSHOT_SERVER_URL` is set, e.g. a local `npx wrangler dev --port 8787 --local`
//! (`http://127.0.0.1:8787`). If the server has `GROUP_CREATE_TOKEN`, pass it
//! in `WARPSHOT_CREATE_TOKEN`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::{sync::Arc, time::Duration};

use tokio::sync::mpsc;
use warpshot_core::{
    client::{Client, ClientError, CreateToken, ErrorCode, Event, Via, WsConfig, api::AppendError},
    keys::{self, IdentityKey, KemKey},
    log::{self, DeviceInfo, GroupId, Log, Op, RecordBody, platform},
    net::store::now_ms,
};

fn device(name: &str, platform: u64) -> DeviceInfo {
    DeviceInfo {
        name: name.into(),
        platform,
        kem_pk: KemKey::generate().unwrap().public_key(),
        app: Some("0.1.0".into()),
    }
}

fn body(log: &Log, subject: &IdentityKey, op: Op) -> RecordBody {
    let (seq, prev) = log.next_position();
    RecordBody {
        group_id: log.group_id(),
        seq,
        prev,
        created_at: now_ms(),
        subject: subject.endpoint_id(),
        op,
    }
}

fn client(url: &str, ik: &Arc<IdentityKey>) -> Client {
    let c = Client::new(url, ik.clone()).unwrap();
    match std::env::var("WARPSHOT_CREATE_TOKEN") {
        Ok(t) if !t.is_empty() => c.with_create_token(CreateToken::new(&t).unwrap()),
        _ => c,
    }
}

async fn next(rx: &mut mpsc::Receiver<Event>) -> Event {
    tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("event timeout")
        .expect("session ended")
}

/// Next event that is not a log push (pushes may interleave with replies).
async fn next_non_log(rx: &mut mpsc::Receiver<Event>) -> Event {
    loop {
        match next(rx).await {
            Event::Log { id: None, .. } => continue,
            e => return e,
        }
    }
}

#[tokio::test]
async fn client_against_server() {
    let Ok(url) = std::env::var("WARPSHOT_SERVER_URL") else {
        eprintln!("WARPSHOT_SERVER_URL not set; skipping");
        return;
    };
    let a = Arc::new(IdentityKey::generate().unwrap());
    let b = Arc::new(IdentityKey::generate().unwrap());
    let outsider = Arc::new(IdentityKey::generate().unwrap());
    let ca = client(&url, &a);
    let cb = client(&url, &b);
    let cx = client(&url, &outsider);

    ca.health().await.unwrap();

    // Genesis.
    let mut gid = [0u8; 16];
    keys::random(&mut gid).unwrap();
    let gid = GroupId(gid);
    let mut local = Log::new(gid);
    let genesis = log::sign_record(
        &a,
        &body(&local, &a, Op::Genesis(device("pc", platform::WINDOWS))),
    );
    local.append(&genesis, now_ms()).unwrap();
    let head = ca.create_group(&genesis).await.unwrap();
    assert_eq!(Some(head), local.head());
    // Second creation: 409 exists.
    assert_eq!(
        ca.create_group(&genesis).await,
        Err(ClientError::Server {
            status: 409,
            code: ErrorCode::Exists
        })
    );

    // Append `add b`.
    let add = log::sign_record(
        &a,
        &body(&local, &b, Op::Add(device("phone", platform::ANDROID))),
    );
    let stale_base = local.clone_records();
    local.append(&add, now_ms()).unwrap();
    let head = ca.append(&gid, &add).await.unwrap();
    assert_eq!(Some(head), local.head());

    // A record built on the old head: 409 head-moved with the current head.
    let stale = log::sign_record(
        &a,
        &body(
            &stale_base,
            &outsider,
            Op::Add(device("x", platform::ANDROID)),
        ),
    );
    assert_eq!(
        ca.append(&gid, &stale).await,
        Err(AppendError::HeadMoved(head))
    );

    // Get the log (full and after seq 0) and validate it locally.
    let page = cb.get_log(&gid, None).await.unwrap();
    assert_eq!(page.head, head);
    assert_eq!(page.records, vec![genesis.clone(), add.clone()]);
    let rebuilt = Log::from_records(gid, page.records.iter().map(Vec::as_slice), now_ms()).unwrap();
    assert!(rebuilt.is_member(&b.endpoint_id()));
    let page = cb.get_log(&gid, Some(0)).await.unwrap();
    assert_eq!(page.records, vec![add.clone()]);

    // Two WebSockets.
    let cfg = WsConfig::default();
    let (wa, mut ea) = ca.websocket(gid, cfg);
    let (wb, mut eb) = cb.websocket(gid, cfg);
    assert_eq!(next(&mut ea).await, Event::Connected);
    assert_eq!(next(&mut eb).await, Event::Connected);

    // Wake over the WebSocket: a → b.
    let mut env = vec![0u8; 700];
    keys::random(&mut env).unwrap();
    let id = wa.wake(&b.endpoint_id(), &env, 60).await.unwrap();
    assert_eq!(next_non_log(&mut ea).await, Event::Ack { id, via: Via::Ws });
    assert_eq!(
        next_non_log(&mut eb).await,
        Event::Wake { env: env.clone() }
    );

    // Wake over HTTP: b → a.
    let via = cb
        .wake(&gid, &a.endpoint_id(), &env[..100], 60)
        .await
        .unwrap();
    assert_eq!(via, Via::Ws);
    assert_eq!(
        next_non_log(&mut ea).await,
        Event::Wake {
            env: env[..100].to_vec()
        }
    );

    // Presence over the WebSocket and over HTTP.
    let id = wb.presence().await.unwrap();
    match next_non_log(&mut eb).await {
        Event::Presence { id: rid, devices } => {
            assert_eq!(rid, id);
            assert_eq!(devices.len(), 2);
            assert!(devices.iter().all(|d| d.online));
        }
        e => panic!("unexpected {e:?}"),
    }
    cb.put_push_token(&gid, "fake-token_123:abc.def")
        .await
        .unwrap();
    let devices = ca.presence(&gid).await.unwrap();
    let pb = devices.iter().find(|d| d.id == b.endpoint_id()).unwrap();
    assert!(pb.online && pb.push && pb.last_seen.is_some());
    cb.delete_push_token(&gid).await.unwrap();
    let devices = ca.presence(&gid).await.unwrap();
    assert!(
        !devices
            .iter()
            .find(|d| d.id == b.endpoint_id())
            .unwrap()
            .push
    );

    // An append is pushed to both sockets; log-get replies with its id.
    let update = log::sign_record(
        &b,
        &body(
            &local,
            &b,
            Op::Update(device("my phone", platform::ANDROID)),
        ),
    );
    local.append(&update, now_ms()).unwrap();
    let head = cb.append(&gid, &update).await.unwrap();
    for rx in [&mut ea, &mut eb] {
        match next(rx).await {
            Event::Log {
                id: None,
                records,
                head: h,
            } => {
                assert_eq!(records, vec![update.clone()]);
                assert_eq!(h, head);
            }
            e => panic!("unexpected {e:?}"),
        }
    }
    let id = wa.log_get(0).await.unwrap();
    match next(&mut ea).await {
        Event::Log {
            id: Some(rid),
            records,
            head: h,
        } => {
            assert_eq!(rid, id);
            assert_eq!(records, vec![add.clone(), update.clone()]);
            assert_eq!(h, head);
        }
        e => panic!("unexpected {e:?}"),
    }

    // A non-member is refused over HTTP and on the WebSocket upgrade.
    let not_member = ClientError::Server {
        status: 403,
        code: ErrorCode::NotMember,
    };
    assert_eq!(cx.get_log(&gid, None).await, Err(not_member));
    assert_eq!(cx.presence(&gid).await, Err(not_member));
    assert_eq!(
        cx.wake(&gid, &a.endpoint_id(), &env, 60).await,
        Err(not_member)
    );
    let (wx, mut ex) = cx.websocket(gid, cfg);
    assert_eq!(next(&mut ex).await, Event::Ended(not_member));
    assert!(!wx.is_connected());
    // Unknown group.
    assert_eq!(
        ca.get_log(&GroupId([0; 16]), None).await,
        Err(ClientError::Server {
            status: 404,
            code: ErrorCode::NoGroup
        })
    );
    // Wake to a non-member.
    assert_eq!(
        ca.wake(&gid, &outsider.endpoint_id(), &env, 60).await,
        Err(not_member)
    );

    // Byte counters (for the idle-network measurement).
    let s = ca.counters();
    eprintln!(
        "client a: {} requests, {} ws connects, {} B out, {} B in",
        s.http_requests, s.ws_connects, s.bytes_out, s.bytes_in
    );
    assert!(s.bytes_in > 0 && s.bytes_out > 0 && s.ws_connects == 1);

    // Keepalive against the real auto-response (§6.3), with a short K.
    let ck = client(&url, &b);
    let fast = WsConfig {
        keepalive: Duration::from_millis(300),
        ..cfg
    };
    let (wk, mut ek) = ck.websocket(gid, fast);
    assert_eq!(next(&mut ek).await, Event::Connected);
    tokio::time::sleep(Duration::from_millis(1600)).await;
    assert!(ek.try_recv().is_err(), "no disconnect expected");
    let s = ck.counters();
    assert!(s.pings >= 4 && s.pongs >= 4 && s.missed_pongs == 0, "{s:?}");
    eprintln!(
        "keepalive: {} pings, {} pongs, {} B out, {} B in (incl. handshake)",
        s.pings, s.pongs, s.bytes_out, s.bytes_in
    );
    wk.close().await;

    wa.close().await;
    wb.close().await;
}

trait CloneRecords {
    fn clone_records(&self) -> Log;
}

impl CloneRecords for Log {
    fn clone_records(&self) -> Log {
        Log::from_records(
            self.group_id(),
            self.records().iter().map(|r| r.raw.as_slice()),
            now_ms(),
        )
        .unwrap()
    }
}

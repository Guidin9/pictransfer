//! Pairing over iroh (protocol §5.3). The UI confirmation and the server
//! submission are injected so the agent, the app and `warpctl` share the flow.

use std::future::Future;

use iroh::{
    Endpoint,
    endpoint::{Connection, RecvStream, SendStream},
};

use super::{
    HANDSHAKE_TIMEOUT, NetError, close, connect, ekm, endpoint_id, read_frame, remote_id,
    store::Device, write_frame,
};
use crate::{
    keys::{self, EndpointId},
    log::{DeviceInfo, GroupId, Log, Op, RecordBody, sign_record},
    pair::{self, PairHello, PairInfo, QrPayload, Resolution, Window, resolve},
    xfer::code,
};

const MAX_MSG: usize = 64 * 1024;
const MAX_DONE: usize = 4 << 20;
const CONFIRM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(pair::WINDOW_SECS);

/// What the user sees before confirming (§5.3 step 6).
#[derive(Debug, Clone)]
pub struct PeerSummary {
    pub id: EndpointId,
    pub device: DeviceInfo,
    pub sas: String,
}

/// Result of a successful pairing: the new validated log to persist.
#[derive(Debug)]
pub struct Paired {
    pub peer: EndpointId,
    pub log: Log,
}

fn context(display: &EndpointId, scanner: &EndpointId) -> Vec<u8> {
    let mut c = display.0.to_vec();
    c.extend_from_slice(&scanner.0);
    c
}

async fn confirm_both<C, CF>(
    send: &mut SendStream,
    recv: &mut RecvStream,
    conn: &Connection,
    summary: PeerSummary,
    confirm: C,
) -> Result<(), NetError>
where
    C: FnOnce(PeerSummary) -> CF,
    CF: Future<Output = bool>,
{
    let local = tokio::time::timeout(CONFIRM_TIMEOUT, confirm(summary))
        .await
        .unwrap_or(false);
    if !local {
        close(conn, code::PAIR_REJECTED);
        return Err(NetError::Rejected);
    }
    write_frame(send, &pair::empty_map()).await?;
    let theirs = read_frame(recv, 16, CONFIRM_TIMEOUT)
        .await
        .map_err(|_| NetError::Rejected)?;
    if !pair::is_empty_map(&theirs) {
        close(conn, code::PROTOCOL);
        return Err(NetError::Rejected);
    }
    Ok(())
}

/// Builds the appender's records on top of `log` (or a new group).
fn build_records(
    dev: &Device,
    log: Option<&Log>,
    other: &EndpointId,
    other_info: &DeviceInfo,
    now_ms: u64,
) -> Result<(Log, Vec<Vec<u8>>), NetError> {
    let mut log = match log {
        Some(l) => l.clone(),
        None => {
            let mut g = [0u8; 16];
            keys::random(&mut g).map_err(|_| NetError::State("rng"))?;
            let mut l = Log::new(GroupId(g));
            let body = RecordBody {
                group_id: l.group_id(),
                seq: 0,
                prev: None,
                created_at: now_ms,
                subject: dev.id(),
                op: Op::Genesis(dev.info()),
            };
            l.append(&sign_record(&dev.keys.ik, &body), now_ms)?;
            l
        }
    };
    let before = log.records().len();
    let (seq, prev) = log.next_position();
    let body = RecordBody {
        group_id: log.group_id(),
        seq,
        prev,
        created_at: now_ms,
        subject: *other,
        op: Op::Add(other_info.clone()),
    };
    log.append(&sign_record(&dev.keys.ik, &body), now_ms)?;
    let new = log
        .records()
        .iter()
        .skip(if dev.log.is_none() { 0 } else { before })
        .map(|r| r.raw.clone())
        .collect();
    Ok((log, new))
}

/// The appender submits, then sends `PairDone` with the full log and waits for `PairOk`.
async fn finish_as_appender<S, SF>(
    send: &mut SendStream,
    recv: &mut RecvStream,
    conn: &Connection,
    log: &Log,
    new: Vec<Vec<u8>>,
    submit: S,
) -> Result<(), NetError>
where
    S: FnOnce(Vec<Vec<u8>>) -> SF,
    SF: Future<Output = Result<(), NetError>>,
{
    if let Err(e) = submit(new).await {
        close(conn, code::INTERNAL);
        return Err(e);
    }
    let all: Vec<Vec<u8>> = log.records().iter().map(|r| r.raw.clone()).collect();
    write_frame(send, &pair::pair_done(&all)).await?;
    let ok = read_frame(recv, 16, HANDSHAKE_TIMEOUT).await?;
    if !pair::is_empty_map(&ok) {
        return Err(NetError::Rejected);
    }
    // The side that receives the last message closes; QUIC close discards unsent data.
    close(conn, code::OK);
    Ok(())
}

/// The other side validates the full log from genesis, requires both devices to
/// be members, replies `PairOk` and closes with 0.
async fn finish_as_receiver(
    send: &mut SendStream,
    recv: &mut RecvStream,
    conn: &Connection,
    me: &EndpointId,
    peer: &EndpointId,
    now_ms: u64,
) -> Result<Log, NetError> {
    let raw = read_frame(recv, MAX_DONE, HANDSHAKE_TIMEOUT).await?;
    let records = pair::parse_pair_done(&raw)?;
    let first = records.first().ok_or(NetError::State("empty log"))?;
    let (body, ..) = crate::log::parse_signed(first)?;
    let log = Log::from_records(body.group_id, records.iter().map(Vec::as_slice), now_ms)
        .map_err(|(_, e)| NetError::Log(e))?;
    if !log.is_member(me) || !log.is_member(peer) {
        close(conn, code::PROTOCOL);
        return Err(NetError::State("pairing log lacks a member"));
    }
    write_frame(send, &pair::empty_map()).await?;
    let _ = send.finish();
    // Wait for the appender to close after reading PairOk.
    let _ = tokio::time::timeout(HANDSHAKE_TIMEOUT, conn.closed()).await;
    Ok(log)
}

/// Display side (the PC): handles one accepted `warpshot/pair/1` connection.
pub async fn display<C, CF, S, SF>(
    ep: &Endpoint,
    conn: Connection,
    window: &mut Window,
    dev: &Device,
    now_ms: u64,
    confirm: C,
    submit: S,
) -> Result<Paired, NetError>
where
    C: FnOnce(PeerSummary) -> CF,
    CF: Future<Output = bool>,
    S: FnOnce(Vec<Vec<u8>>) -> SF,
    SF: Future<Output = Result<(), NetError>>,
{
    let me = endpoint_id(ep);
    let scanner = remote_id(&conn);
    let (mut send, mut recv) = tokio::time::timeout(HANDSHAKE_TIMEOUT, conn.accept_bi())
        .await
        .map_err(|_| NetError::Timeout)?
        .map_err(|_| NetError::Stream("accept"))?;
    let hello = PairHello::parse(&read_frame(&mut recv, MAX_MSG, HANDSHAKE_TIMEOUT).await?)?;
    let k = ekm(&conn, pair::EKM_LABEL, &context(&me, &scanner))?;
    if let Err(e) = window.check(&k, &scanner, &hello.proof, now_ms / 1000) {
        let e = NetError::Pair(e);
        close(&conn, e.close_code());
        return Err(e);
    }
    // §5.3 step 4: different groups end here, before any SAS is shown.
    if resolve(dev.group_id(), hello.group) == Resolution::OtherGroup {
        close(&conn, code::PAIR_OTHER_GROUP);
        return Err(NetError::Closed(code::PAIR_OTHER_GROUP));
    }
    write_frame(
        &mut send,
        &PairInfo {
            device: dev.info(),
            group: dev.group_id(),
            head: dev.head(),
        }
        .encode(),
    )
    .await?;
    confirm_both(
        &mut send,
        &mut recv,
        &conn,
        PeerSummary {
            id: scanner,
            device: hello.device.clone(),
            sas: pair::sas(&k),
        },
        confirm,
    )
    .await?;
    match resolve(dev.group_id(), hello.group) {
        Resolution::NewGroup | Resolution::DisplayAdds(_) => {
            let (log, new) = build_records(dev, dev.log.as_ref(), &scanner, &hello.device, now_ms)?;
            finish_as_appender(&mut send, &mut recv, &conn, &log, new, submit).await?;
            Ok(Paired { peer: scanner, log })
        }
        Resolution::ScannerAdds(_) => Ok(Paired {
            peer: scanner,
            log: finish_as_receiver(&mut send, &mut recv, &conn, &me, &scanner, now_ms).await?,
        }),
        Resolution::AlreadyPaired(_) => {
            let log = dev.log.clone().ok_or(NetError::State("no log"))?;
            finish_as_appender(&mut send, &mut recv, &conn, &log, vec![], |_| async {
                Ok(())
            })
            .await?;
            Ok(Paired { peer: scanner, log })
        }
        Resolution::OtherGroup => {
            close(&conn, code::PAIR_OTHER_GROUP);
            Err(NetError::Closed(code::PAIR_OTHER_GROUP))
        }
    }
}

/// Scanner side (the phone, or `warpctl pair-scan`).
pub async fn scan<C, CF, S, SF>(
    ep: &Endpoint,
    qr: &QrPayload,
    dev: &Device,
    now_ms: u64,
    confirm: C,
    submit: S,
) -> Result<Paired, NetError>
where
    C: FnOnce(PeerSummary) -> CF,
    CF: Future<Output = bool>,
    S: FnOnce(Vec<Vec<u8>>) -> SF,
    SF: Future<Output = Result<(), NetError>>,
{
    if now_ms / 1000 > qr.exp {
        return Err(NetError::Pair(crate::pair::PairError::Expired));
    }
    let me = endpoint_id(ep);
    let conn = connect(ep, &qr.eid, &qr.dial, pair::ALPN).await?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|_| NetError::Stream("open_bi"))?;
    let k = ekm(&conn, pair::EKM_LABEL, &context(&qr.eid, &me))?;
    let hello = PairHello {
        device: dev.info(),
        proof: pair::proof(&qr.secret, &k, &me),
        group: dev.group_id(),
        head: dev.head(),
    };
    write_frame(&mut send, &hello.encode()).await?;
    let info = PairInfo::parse(
        &read_frame(&mut recv, MAX_MSG, HANDSHAKE_TIMEOUT)
            .await
            .map_err(|e| super::explain(&conn, e))?,
    )?;
    confirm_both(
        &mut send,
        &mut recv,
        &conn,
        PeerSummary {
            id: qr.eid,
            device: info.device.clone(),
            sas: pair::sas(&k),
        },
        confirm,
    )
    .await?;
    match resolve(info.group, dev.group_id()) {
        Resolution::ScannerAdds(_) => {
            let (log, new) = build_records(dev, dev.log.as_ref(), &qr.eid, &info.device, now_ms)?;
            finish_as_appender(&mut send, &mut recv, &conn, &log, new, submit).await?;
            Ok(Paired { peer: qr.eid, log })
        }
        Resolution::NewGroup | Resolution::DisplayAdds(_) | Resolution::AlreadyPaired(_) => {
            Ok(Paired {
                peer: qr.eid,
                log: finish_as_receiver(&mut send, &mut recv, &conn, &me, &qr.eid, now_ms).await?,
            })
        }
        Resolution::OtherGroup => {
            close(&conn, code::PAIR_OTHER_GROUP);
            Err(NetError::Closed(code::PAIR_OTHER_GROUP))
        }
    }
}

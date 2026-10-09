//! Membership log ⇄ server (protocol §4.4, §4.5): submit appended records and
//! pull new ones, validating them as a continuation of the local log.

use super::NetError;
use crate::{
    client::{Client, api::AppendError},
    log::{Head, Incoming, Log, parse_signed},
};

/// Submits records in order: a genesis creates the group, the rest are appended.
pub async fn submit(client: &Client, records: &[Vec<u8>]) -> Result<Option<Head>, NetError> {
    let mut head = None;
    for raw in records {
        let (body, ..) = parse_signed(raw)?;
        head = Some(if body.seq == 0 {
            client.create_group(raw).await?
        } else {
            match client.append(&body.group_id, raw).await {
                Ok(h) => h,
                Err(AppendError::HeadMoved(_)) => return Err(NetError::HeadMoved),
                Err(AppendError::Client(e)) => return Err(e.into()),
            }
        });
    }
    Ok(head)
}

/// Fetches records after the local head and appends the valid continuation.
/// A record that conflicts with a local one is a fork (§4.5). Returns true if
/// the log changed (the caller persists it and raises §4.6 alerts for new adds).
pub async fn pull(client: &Client, log: &mut Log, now_ms: u64) -> Result<bool, NetError> {
    let after = log.head().map(|h| h.seq);
    let page = client.get_log(&log.group_id(), after).await?;
    let mut changed = false;
    for raw in &page.records {
        let rec = log.check(raw, now_ms);
        match rec {
            Ok(r) => match log.classify(r.body.seq, &r.id) {
                Incoming::Next => {
                    log.append(raw, now_ms)?;
                    changed = true;
                }
                Incoming::Known => {}
                Incoming::Fork => return Err(NetError::Fork),
                Incoming::Gap => return Err(NetError::State("log gap from server")),
            },
            Err(e) => {
                // A record at an existing seq with a different id is a fork even if it
                // does not validate as the next record.
                let (body, raw_body, signer, sig) = parse_signed(raw)?;
                let id = crate::log::record_id(&raw_body, &signer, &sig);
                if log.classify(body.seq, &id) == Incoming::Fork {
                    return Err(NetError::Fork);
                }
                return Err(NetError::Log(e));
            }
        }
    }
    if let Some(local) = log.head()
        && page.head.seq == local.seq
        && page.head.id != local.id
    {
        return Err(NetError::Fork);
    }
    Ok(changed)
}

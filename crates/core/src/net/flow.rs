//! Wake-driven transfer flow (protocol §7.4, §8.4 "who sends Offer", §9
//! pending sessions): the sender seals a `connect` wake and waits; the woken
//! recipient dials the sender, which then offers its items.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use iroh::Endpoint;

use super::{NetError, dial_info, store::Device, xfer as nx};
use crate::{
    keys::{self, EndpointId},
    log::Log,
    wake::{self, Inner, Kind, Preview},
};

/// §9: the sender keeps items ready this long after sending a wake.
pub const PENDING_TTL: Duration = Duration::from_secs(120);

/// Items waiting for the woken recipient to dial in.
#[derive(Debug)]
pub struct Pending {
    pub target: EndpointId,
    pub items: Vec<nx::OutItem>,
    created: Instant,
}

/// Sender-side pending sessions keyed by the 16-byte session id.
#[derive(Debug, Default)]
pub struct PendingSessions {
    map: HashMap<[u8; 16], Pending>,
}

impl PendingSessions {
    pub fn insert(
        &mut self,
        target: EndpointId,
        items: Vec<nx::OutItem>,
    ) -> Result<[u8; 16], NetError> {
        self.expire();
        let mut session = [0u8; 16];
        loop {
            keys::random(&mut session).map_err(|_| NetError::State("rng"))?;
            // All-zero means "no session" (§8.3).
            if session != [0; 16] && !self.map.contains_key(&session) {
                break;
            }
        }
        self.map.insert(
            session,
            Pending {
                target,
                items,
                created: Instant::now(),
            },
        );
        Ok(session)
    }

    /// Claims the pending session presented in `Hello`, if it belongs to `peer`.
    pub fn take(&mut self, session: &[u8; 16], peer: &EndpointId) -> Option<Pending> {
        self.expire();
        match self.map.get(session) {
            Some(p) if p.target == *peer => self.map.remove(session),
            _ => None,
        }
    }

    /// Drops expired sessions and returns their targets (to tell the user).
    pub fn expire(&mut self) -> Vec<EndpointId> {
        let mut gone = Vec::new();
        self.map.retain(|_, p| {
            let keep = p.created.elapsed() < PENDING_TTL;
            if !keep {
                gone.push(p.target);
            }
            keep
        });
        gone
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Builds the `connect` wake envelope for `target` (sealed to its KEM key from the log).
pub fn connect_wake(
    ep: &Endpoint,
    dev: &Device,
    target: &EndpointId,
    session: [u8; 16],
    items: &[nx::OutItem],
    now_ms: u64,
) -> Result<Vec<u8>, NetError> {
    let log = dev.log.as_ref().ok_or(NetError::State("not paired"))?;
    let info = log.members().get(target).ok_or(NetError::Identity)?;
    let mut nonce = [0u8; 16];
    keys::random(&mut nonce).map_err(|_| NetError::State("rng"))?;
    let mut kinds: Vec<u64> = items.iter().map(|o| o.item.kind).collect();
    kinds.sort_unstable();
    kinds.dedup();
    let inner = Inner {
        kind: Kind::Connect {
            session,
            dial: dial_info(ep),
            preview: Some(Preview {
                count: items.len() as u64,
                total_size: items
                    .iter()
                    .map(|o| o.item.size)
                    .fold(0u64, u64::saturating_add),
                kinds,
            }),
        },
        ts: now_ms,
        nonce,
        group_id: log.group_id(),
        head: log.head().ok_or(NetError::State("no log"))?,
    };
    wake::seal(&dev.keys.ik, target, &info.kem_pk, &inner).map_err(|_| NetError::State("seal"))
}

/// Builds a `group-changed` wake for `target`.
pub fn group_changed_wake(
    dev: &Device,
    target: &EndpointId,
    now_ms: u64,
) -> Result<Vec<u8>, NetError> {
    let log = dev.log.as_ref().ok_or(NetError::State("not paired"))?;
    let info = log.members().get(target).ok_or(NetError::Identity)?;
    let mut nonce = [0u8; 16];
    keys::random(&mut nonce).map_err(|_| NetError::State("rng"))?;
    let inner = Inner {
        kind: Kind::GroupChanged,
        ts: now_ms,
        nonce,
        group_id: log.group_id(),
        head: log.head().ok_or(NetError::State("no log"))?,
    };
    wake::seal(&dev.keys.ik, target, &info.kem_pk, &inner).map_err(|_| NetError::State("seal"))
}

/// What a received envelope asks for.
#[derive(Debug)]
pub enum WakeAction {
    /// Dial `sender` with `session` and receive its items.
    Connect {
        sender: EndpointId,
        session: [u8; 16],
        dial: wake::DialInfo,
        preview: Option<Preview>,
    },
    /// Sync the log from the server and raise §4.6 alerts.
    GroupChanged,
}

/// §7.3: opens and authorizes an envelope. `NeedSync` means: fetch the log from
/// the server, validate it, then call again.
pub fn open_wake(
    dev: &Device,
    env: &[u8],
    now_ms: u64,
    replay: &mut wake::ReplayCache,
) -> Result<(EndpointId, WakeAction), wake::WakeError> {
    let log: &Log = dev.log.as_ref().ok_or(wake::WakeError::NotMember)?;
    let me = dev.id();
    let my_kid = keys::kid(&dev.keys.kk.public_key());
    let opened = wake::open(env, &me, |k| (*k == my_kid).then_some(&dev.keys.kk))?;
    let inner = wake::authorize(&opened, &me, log, now_ms, replay)?;
    let action = match inner.kind {
        Kind::Connect {
            session,
            dial,
            preview,
        } => WakeAction::Connect {
            sender: opened.sender,
            session,
            dial,
            preview,
        },
        Kind::GroupChanged => WakeAction::GroupChanged,
    };
    Ok((opened.sender, action))
}

/// The woken recipient dials the sender with the session (§7.4) and returns the
/// keyed session; the sender (listener) will send the `Offer`.
pub async fn answer_connect(
    ep: &Endpoint,
    log: &Log,
    sender: &EndpointId,
    session: [u8; 16],
    dial: &wake::DialInfo,
) -> Result<nx::Session, NetError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        nx::dial(ep, log, sender, dial, session),
    )
    .await
    .map_err(|_| NetError::Timeout)?
}

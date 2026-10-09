//! On-demand endpoint lifetime (protocol §9, resource budget §2.3): the iroh
//! endpoint exists only while there is work and closes after 30 s of idleness.
//! Event-driven: the reaper waits on a notification and sleeps only while an
//! idle endpoint exists — no polling.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use iroh::Endpoint;
use tokio::sync::{Mutex, Notify};
use zeroize::Zeroizing;

use super::{NetError, Relay, bind};
use crate::keys::IdentityKey;

pub const IDLE_CLOSE: Duration = Duration::from_secs(30);

type Hook = Box<dyn Fn() + Send + Sync>;

pub struct EndpointManager {
    secret: Zeroizing<[u8; 32]>,
    relay: Relay,
    idle_after: Duration,
    ep: Mutex<Option<Endpoint>>,
    users: AtomicUsize,
    changed: Notify,
    on_closed: Option<Hook>,
}

impl std::fmt::Debug for EndpointManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EndpointManager(users={})",
            self.users.load(Ordering::Relaxed)
        )
    }
}

/// Keeps the endpoint alive while held (a connection, a pending session, a
/// pairing window, or the Android UI in the foreground).
#[derive(Debug)]
pub struct Lease {
    mgr: Arc<EndpointManager>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.mgr.users.fetch_sub(1, Ordering::AcqRel);
        self.mgr.changed.notify_one();
    }
}

impl EndpointManager {
    /// `on_closed` runs after an idle close (the agent trims its working set there).
    pub fn new(ik: &IdentityKey, relay: Relay, on_closed: Option<Hook>) -> Arc<Self> {
        Self::with_idle(ik, relay, IDLE_CLOSE, on_closed)
    }

    pub fn with_idle(
        ik: &IdentityKey,
        relay: Relay,
        idle_after: Duration,
        on_closed: Option<Hook>,
    ) -> Arc<Self> {
        Arc::new(Self {
            secret: ik.secret(),
            relay,
            idle_after,
            ep: Mutex::new(None),
            users: AtomicUsize::new(0),
            changed: Notify::new(),
            on_closed,
        })
    }

    /// Returns the endpoint, binding it on first use, plus a lease.
    pub async fn acquire(self: &Arc<Self>) -> Result<(Endpoint, Lease), NetError> {
        let mut guard = self.ep.lock().await;
        self.users.fetch_add(1, Ordering::AcqRel);
        let lease = Lease {
            mgr: Arc::clone(self),
        };
        if let Some(ep) = guard.as_ref().filter(|e| !e.is_closed()) {
            return Ok((ep.clone(), lease));
        }
        let ep = bind(&IdentityKey::from_secret(&self.secret), self.relay).await?;
        *guard = Some(ep.clone());
        drop(guard);
        self.changed.notify_one();
        Ok((ep, lease))
    }

    pub async fn is_open(&self) -> bool {
        self.ep
            .lock()
            .await
            .as_ref()
            .is_some_and(|e| !e.is_closed())
    }

    pub fn users(&self) -> usize {
        self.users.load(Ordering::Acquire)
    }

    /// Runs forever: closes the endpoint once it has had no users for `idle_after`.
    pub async fn run_reaper(self: Arc<Self>) {
        loop {
            self.changed.notified().await;
            // Wait out the idle period; any acquire/release restarts it.
            loop {
                if self.users() > 0 || !self.is_open().await {
                    break;
                }
                tokio::select! {
                    _ = tokio::time::sleep(self.idle_after) => {
                        let mut guard = self.ep.lock().await;
                        if self.users() == 0
                            && let Some(ep) = guard.take()
                        {
                            ep.close().await;
                            drop(guard);
                            if let Some(h) = &self.on_closed {
                                h();
                            }
                        }
                        break;
                    }
                    _ = self.changed.notified() => {}
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use super::*;

    #[tokio::test(flavor = "current_thread", start_paused = false)]
    async fn binds_on_demand_and_closes_when_idle() {
        let ik = IdentityKey::from_secret(&[4; 32]);
        let closed = Arc::new(AtomicBool::new(false));
        let c2 = Arc::clone(&closed);
        let mgr = EndpointManager::with_idle(
            &ik,
            Relay::Disabled,
            Duration::from_millis(300),
            Some(Box::new(move || c2.store(true, Ordering::SeqCst))),
        );
        tokio::spawn(Arc::clone(&mgr).run_reaper());
        assert!(!mgr.is_open().await);
        let (ep1, l1) = mgr.acquire().await.unwrap();
        let (ep2, l2) = mgr.acquire().await.unwrap();
        assert_eq!(ep1.id(), ep2.id(), "one shared endpoint");
        drop(l1);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(mgr.is_open().await, "still leased");
        drop(l2);
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(mgr.is_open().await, "within the idle period");
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(!mgr.is_open().await, "closed after idle");
        assert!(closed.load(Ordering::SeqCst));
        // Re-acquire binds a fresh endpoint.
        let (_ep3, _l3) = mgr.acquire().await.unwrap();
        assert!(mgr.is_open().await);
    }
}

//! Admission and runtime execution are separate: a transaction may wait for
//! convergence while keeping other requests out, without locking its worker out.
use std::collections::HashMap;
use std::sync::{Arc, Weak};

use tokio::sync::{
    Mutex, MutexGuard, OwnedMutexGuard, OwnedRwLockReadGuard, RwLock, RwLockReadGuard,
    RwLockWriteGuard,
};

#[derive(Debug, Clone, Default)]
pub struct InterfaceMutationLocks {
    locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    // Identity sessions follow the application's shared mutation scope, even
    // when API and convergence use separate netlink connections.
    pub(crate) mac_sessions: Arc<Mutex<super::interface::mac::MacSessions>>,
}

impl InterfaceMutationLocks {
    /// Serialize mutations of one interface until the returned guard is dropped.
    /// Other interfaces can acquire their own locks independently.
    pub async fn lock(&self, interface: &str) -> OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.locks.lock().await;
            locks
                .entry(interface.to_owned())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        lock.lock_owned().await
    }
    /// Recovery sweeps skip a scope already owned by a live transaction. Waiting
    /// here could block the very converger that transaction needs to finish.
    pub(crate) async fn try_lock(&self, interface: &str) -> Option<OwnedMutexGuard<()>> {
        let lock = {
            let mut locks = self.locks.lock().await;
            locks
                .entry(interface.to_owned())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        lock.try_lock_owned().ok()
    }
}

#[derive(Default)]
pub struct NetworkMutationGate {
    admission: Mutex<()>,
    runtime: Arc<RwLock<()>>,
    convergence: std::sync::Mutex<Weak<OwnedRwLockReadGuard<()>>>,
    convergence_changed: tokio::sync::Notify,
}

impl NetworkMutationGate {
    /// Reserve admission for one control operation without preventing background convergence.
    pub async fn admit(&self) -> MutexGuard<'_, ()> {
        self.admission.lock().await
    }

    /// Desired-state/background audits that are safe to run concurrently.
    pub async fn read(&self) -> RwLockReadGuard<'_, ()> {
        self.runtime.read().await
    }

    /// The converger owns one shared reservation until its in-flight work is
    /// drained. Interface compensation can join it even if a global writer is
    /// queued; queuing another read behind that writer would delay rollback
    /// until an unrelated radio finished. Interface lanes serialize participants.
    pub(crate) async fn converge(&self) -> Arc<OwnedRwLockReadGuard<()>> {
        let reservation = Arc::new(self.runtime.clone().read_owned().await);
        *self.convergence.lock().expect("convergence reservation") = Arc::downgrade(&reservation);
        self.convergence_changed.notify_waiters();
        reservation
    }

    pub(crate) async fn participate(&self) -> Arc<OwnedRwLockReadGuard<()>> {
        loop {
            let changed = self.convergence_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(reservation) = self
                .convergence
                .lock()
                .expect("convergence reservation")
                .upgrade()
            {
                return reservation;
            }
            tokio::select! {
                reservation = self.runtime.clone().read_owned() => return Arc::new(reservation),
                _ = changed => {}
            }
        }
    }

    /// Exclude concurrent runtime writers. Callers may already hold admission,
    /// or may be autonomous background writers such as process liveness repair.
    pub async fn execute(&self) -> RwLockWriteGuard<'_, ()> {
        self.runtime.write().await
    }

    /// Acquire admission before exclusive runtime access, returning both guards.
    /// This order lets convergence progress while another mutation waits for admission.
    pub async fn write(&self) -> (MutexGuard<'_, ()>, RwLockWriteGuard<'_, ()>) {
        let admission = self.admit().await;
        let runtime = self.execute().await;
        (admission, runtime)
    }
}

// A cancellation request is independent of runtime locks. Only the operation
// owner observes it at a compensatable boundary; storage workers keep running.
tokio::task_local! {
    static OPERATION_CANCELLATION: tokio::sync::watch::Receiver<bool>;
}

pub(crate) async fn cancellation_scope<T>(
    receiver: tokio::sync::watch::Receiver<bool>,
    future: impl std::future::Future<Output = T>,
) -> T {
    OPERATION_CANCELLATION.scope(receiver, future).await
}

pub(crate) async fn cancellation_requested() {
    let Ok(mut receiver) = OPERATION_CANCELLATION.try_with(Clone::clone) else {
        return std::future::pending::<()>().await;
    };
    loop {
        if *receiver.borrow_and_update() {
            return;
        }
        if receiver.changed().await.is_err() {
            return std::future::pending::<()>().await;
        }
    }
}

pub(crate) fn current_cancellation() -> Option<tokio::sync::watch::Receiver<bool>> {
    OPERATION_CANCELLATION.try_with(Clone::clone).ok()
}

/// Only observational readiness waits use this helper. Runtime/storage writes
/// retain their own completion and ownership protocols.
pub(crate) async fn cancellable_wait<T>(
    future: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    tokio::select! {
        biased;
        () = cancellation_requested() => anyhow::bail!("operation cancelled by operator"),
        result = future => result,
    }
}

#[cfg(test)]
mod tests;

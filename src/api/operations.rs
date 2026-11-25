use std::future::Future;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinSet;

const MAX_OPERATIONS: usize = 128;
const SHUTDOWN_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Clone, Default)]
pub(crate) struct Operations(Arc<Mutex<State>>);

#[derive(Default)]
struct State {
    closed: bool,
    tasks: JoinSet<()>,
    cancellable: std::collections::HashMap<String, CancellableOperation>,
}

struct CancellableOperation {
    sender: tokio::sync::watch::Sender<bool>,
    active: Arc<std::sync::atomic::AtomicBool>,
}

impl Operations {
    /// Accepted work outlives its caller. Optional cancellation identities are
    /// registered under the same admission lock and never reused in this session.
    pub(crate) async fn run<T: Send + 'static>(
        &self,
        id: Option<String>,
        operation: impl Future<Output = T> + Send + 'static,
    ) -> Result<T> {
        if let Some(id) = &id {
            anyhow::ensure!(
                !id.is_empty()
                    && id.len() <= 96
                    && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
                "invalid operation identity"
            );
        }
        let (sender, receiver) = oneshot::channel();
        {
            let mut state = self.0.lock().await;
            while let Some(result) = state.tasks.try_join_next() {
                if let Err(error) = result {
                    tracing::error!(%error, "control operation failed");
                }
            }
            if state.closed {
                bail!("control service is stopping");
            }
            if state.tasks.len() >= MAX_OPERATIONS {
                bail!("control service is busy; retry later");
            }
            let cancellation = if let Some(id) = id {
                anyhow::ensure!(
                    !state.cancellable.contains_key(&id),
                    "operation identity already used"
                );
                anyhow::ensure!(
                    state.cancellable.len() < 65536,
                    "cancellable operation identity limit reached"
                );
                let (cancel, cancelled) = tokio::sync::watch::channel(false);
                let active = Arc::new(std::sync::atomic::AtomicBool::new(true));
                state.cancellable.insert(
                    id,
                    CancellableOperation {
                        sender: cancel,
                        active: active.clone(),
                    },
                );
                Some((cancelled, ActiveRegistration(active)))
            } else {
                None
            };
            state.tasks.spawn(async move {
                let result = match cancellation {
                    Some((cancelled, registration)) => {
                        let result =
                            crate::core::mutation::cancellation_scope(cancelled, operation).await;
                        drop(registration);
                        result
                    }
                    None => operation.await,
                };
                let _ = sender.send(result);
            });
        }
        receiver.await.context("control operation failed")
    }

    pub(crate) async fn cancel(&self, id: &str) -> Result<()> {
        let state = self.0.lock().await;
        let operation = state
            .cancellable
            .get(id)
            .context("operation is not cancellable or is no longer active")?;
        anyhow::ensure!(
            operation.active.load(std::sync::atomic::Ordering::Acquire),
            "operation already finished"
        );
        operation
            .sender
            .send(true)
            .context("operation already finished")
    }

    /// Stop admission and drain accepted tasks up to the shutdown deadline.
    /// Stalled tasks are cancelled; mutation guards retain their recovery proof.
    pub(crate) async fn close(&self) {
        let mut state = self.0.lock().await;
        state.closed = true;
        let drain = async {
            while let Some(result) = state.tasks.join_next().await {
                if let Err(error) = result {
                    tracing::error!(%error, "control operation failed during shutdown");
                }
            }
        };
        if tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, drain)
            .await
            .is_err()
        {
            tracing::warn!(remaining = state.tasks.len(), "control shutdown deadline reached; cancelling stalled operations and retaining recovery journals");
            state.tasks.abort_all();
            while let Some(result) = state.tasks.join_next().await {
                if let Err(error) = result {
                    if !error.is_cancelled() {
                        tracing::error!(%error, "control operation failed during shutdown");
                    }
                }
            }
        }
    }
}

struct ActiveRegistration(Arc<std::sync::atomic::AtomicBool>);
impl Drop for ActiveRegistration {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Release);
    }
}

#[cfg(test)]
mod tests;

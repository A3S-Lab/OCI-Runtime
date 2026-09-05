use std::future::Future;
use std::pin::Pin;

type CleanupFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
type CleanupFactory = Box<dyn FnOnce() -> CleanupFuture + Send + 'static>;

/// Runs an asynchronous cleanup operation independently if its owner future is
/// dropped while the cleanup is still armed.
///
/// Rust cannot await from `Drop`.  Keeping the operation in a detached Tokio
/// task preserves cleanup across cancellation while retaining the normal
/// synchronous drop fallback when the runtime itself is already gone.  Callers
/// must disarm the guard immediately after publishing ownership elsewhere.
pub(crate) struct DetachedAsyncCleanup {
    cleanup: Option<CleanupFactory>,
}

impl DetachedAsyncCleanup {
    /// Arm one cleanup closure. The closure and returned future must be owned
    /// and `Send` because cancellation may schedule them on another worker.
    pub(crate) fn new<F, Fut>(cleanup: F) -> Self
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        Self {
            cleanup: Some(Box::new(move || Box::pin(cleanup()))),
        }
    }

    /// Transfer cleanup ownership to the normal lifecycle owner.
    pub(crate) fn disarm(&mut self) {
        self.cleanup = None;
    }
}

impl Drop for DetachedAsyncCleanup {
    fn drop(&mut self) {
        let Some(cleanup) = self.cleanup.take() else {
            return;
        };
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            // The closure is dropped here, releasing its owner and allowing
            // any synchronous process-level fallback to run.
            return;
        };
        drop(handle.spawn(cleanup()));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use super::DetachedAsyncCleanup;

    #[tokio::test]
    async fn dropped_guard_detaches_cleanup_to_the_current_runtime() {
        let calls = Arc::new(AtomicUsize::new(0));
        let cleanup_calls = Arc::clone(&calls);
        drop(DetachedAsyncCleanup::new(move || async move {
            cleanup_calls.fetch_add(1, Ordering::Relaxed);
        }));

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if calls.load(Ordering::Relaxed) == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached cleanup should run");
    }

    #[tokio::test]
    async fn disarmed_guard_does_not_run_cleanup() {
        let calls = Arc::new(AtomicUsize::new(0));
        let cleanup_calls = Arc::clone(&calls);
        let mut guard = DetachedAsyncCleanup::new(move || async move {
            cleanup_calls.fetch_add(1, Ordering::Relaxed);
        });
        guard.disarm();
        drop(guard);
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }
}

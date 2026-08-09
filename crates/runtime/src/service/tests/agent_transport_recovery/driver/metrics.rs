use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Default)]
pub(in super::super) struct DriverMetrics {
    pub(super) create_dispatches: AtomicUsize,
    pub(super) state_dispatches: AtomicUsize,
    pub(super) start_dispatches: AtomicUsize,
    pub(super) kill_dispatches: AtomicUsize,
    pub(super) delete_dispatches: AtomicUsize,
    pub(super) wait_dispatches: AtomicUsize,
    pub(super) exec_dispatches: AtomicUsize,
    pub(super) signal_process_dispatches: AtomicUsize,
    pub(super) wait_process_dispatches: AtomicUsize,
    pub(super) pause_dispatches: AtomicUsize,
    pub(super) resume_dispatches: AtomicUsize,
    pub(super) processes_dispatches: AtomicUsize,
    pub(super) update_dispatches: AtomicUsize,
    pub(super) stats_dispatches: AtomicUsize,
    pub(super) read_output_dispatches: AtomicUsize,
    pub(super) write_stdin_dispatches: AtomicUsize,
    pub(super) close_stdin_dispatches: AtomicUsize,
    pub(super) resize_dispatches: AtomicUsize,
    pub(super) file_dispatches: AtomicUsize,
    pub(super) recoveries: AtomicUsize,
}

impl DriverMetrics {
    pub(in super::super) fn create_dispatches(&self) -> usize {
        self.create_dispatches.load(Ordering::SeqCst)
    }

    pub(in super::super) fn state_dispatches(&self) -> usize {
        self.state_dispatches.load(Ordering::SeqCst)
    }

    pub(in super::super) fn start_dispatches(&self) -> usize {
        self.start_dispatches.load(Ordering::SeqCst)
    }

    pub(in super::super) fn kill_dispatches(&self) -> usize {
        self.kill_dispatches.load(Ordering::SeqCst)
    }

    pub(in super::super) fn delete_dispatches(&self) -> usize {
        self.delete_dispatches.load(Ordering::SeqCst)
    }

    pub(in super::super) fn wait_dispatches(&self) -> usize {
        self.wait_dispatches.load(Ordering::SeqCst)
    }

    pub(in super::super) fn exec_dispatches(&self) -> usize {
        self.exec_dispatches.load(Ordering::SeqCst)
    }

    pub(in super::super) fn signal_process_dispatches(&self) -> usize {
        self.signal_process_dispatches.load(Ordering::SeqCst)
    }

    pub(in super::super) fn wait_process_dispatches(&self) -> usize {
        self.wait_process_dispatches.load(Ordering::SeqCst)
    }

    pub(in super::super) fn pause_dispatches(&self) -> usize {
        self.pause_dispatches.load(Ordering::SeqCst)
    }

    pub(in super::super) fn resume_dispatches(&self) -> usize {
        self.resume_dispatches.load(Ordering::SeqCst)
    }

    pub(in super::super) fn processes_dispatches(&self) -> usize {
        self.processes_dispatches.load(Ordering::SeqCst)
    }

    pub(in super::super) fn update_dispatches(&self) -> usize {
        self.update_dispatches.load(Ordering::SeqCst)
    }

    pub(in super::super) fn stats_dispatches(&self) -> usize {
        self.stats_dispatches.load(Ordering::SeqCst)
    }

    pub(in super::super) fn read_output_dispatches(&self) -> usize {
        self.read_output_dispatches.load(Ordering::SeqCst)
    }

    pub(in super::super) fn write_stdin_dispatches(&self) -> usize {
        self.write_stdin_dispatches.load(Ordering::SeqCst)
    }

    pub(in super::super) fn close_stdin_dispatches(&self) -> usize {
        self.close_stdin_dispatches.load(Ordering::SeqCst)
    }

    pub(in super::super) fn resize_dispatches(&self) -> usize {
        self.resize_dispatches.load(Ordering::SeqCst)
    }

    pub(in super::super) fn file_dispatches(&self) -> usize {
        self.file_dispatches.load(Ordering::SeqCst)
    }

    pub(in super::super) fn recoveries(&self) -> usize {
        self.recoveries.load(Ordering::SeqCst)
    }
}

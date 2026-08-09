use super::JournaledLifecycleGuest;

impl JournaledLifecycleGuest {
    pub(in super::super) fn create_request_count(&self) -> usize {
        self.journal
            .lock()
            .expect("guest journal lock")
            .create
            .requests
    }

    pub(in super::super) fn create_effect_count(&self) -> usize {
        self.journal
            .lock()
            .expect("guest journal lock")
            .create
            .effects
    }

    pub(in super::super) fn state_request_count(&self) -> usize {
        self.journal
            .lock()
            .expect("guest journal lock")
            .state_requests
    }

    pub(in super::super) fn start_request_count(&self) -> usize {
        self.journal
            .lock()
            .expect("guest journal lock")
            .start
            .requests
    }

    pub(in super::super) fn start_effect_count(&self) -> usize {
        self.journal
            .lock()
            .expect("guest journal lock")
            .start
            .effects
    }

    pub(in super::super) fn kill_request_count(&self) -> usize {
        self.journal
            .lock()
            .expect("guest journal lock")
            .kill
            .requests
    }

    pub(in super::super) fn kill_effect_count(&self) -> usize {
        self.journal
            .lock()
            .expect("guest journal lock")
            .kill
            .effects
    }

    pub(in super::super) fn delete_request_count(&self) -> usize {
        self.journal
            .lock()
            .expect("guest journal lock")
            .delete
            .requests
    }

    pub(in super::super) fn delete_effect_count(&self) -> usize {
        self.journal
            .lock()
            .expect("guest journal lock")
            .delete
            .effects
    }

    pub(in super::super) fn wait_request_count(&self) -> usize {
        self.journal
            .lock()
            .expect("guest journal lock")
            .wait_requests
    }

    pub(in super::super) fn exec_request_count(&self) -> usize {
        self.journal
            .lock()
            .expect("guest journal lock")
            .exec
            .requests
    }

    pub(in super::super) fn exec_effect_count(&self) -> usize {
        self.journal
            .lock()
            .expect("guest journal lock")
            .exec
            .effects
    }

    pub(in super::super) fn signal_process_request_count(&self) -> usize {
        self.journal
            .lock()
            .expect("guest journal lock")
            .signal_process
            .requests
    }

    pub(in super::super) fn signal_process_effect_count(&self) -> usize {
        self.journal
            .lock()
            .expect("guest journal lock")
            .signal_process
            .effects
    }

    pub(in super::super) fn wait_process_request_count(&self) -> usize {
        self.journal
            .lock()
            .expect("guest journal lock")
            .wait_process_requests
    }
}

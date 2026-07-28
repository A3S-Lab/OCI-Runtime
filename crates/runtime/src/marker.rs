#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExactMarkerState {
    Complete,
    InProgress,
    Mismatch,
}

pub(crate) fn exact_marker_state(observed: &[u8], expected: &[u8]) -> ExactMarkerState {
    if observed == expected {
        ExactMarkerState::Complete
    } else if expected.starts_with(observed) {
        ExactMarkerState::InProgress
    } else {
        ExactMarkerState::Mismatch
    }
}

#[cfg(test)]
mod tests {
    use super::{exact_marker_state, ExactMarkerState};

    const EXPECTED: &[u8] = b"complete marker\n";

    #[test]
    fn exact_marker_write_state_distinguishes_partial_and_invalid_data() {
        assert_eq!(
            exact_marker_state(EXPECTED, EXPECTED),
            ExactMarkerState::Complete
        );
        assert_eq!(
            exact_marker_state(b"", EXPECTED),
            ExactMarkerState::InProgress
        );
        assert_eq!(
            exact_marker_state(b"complete", EXPECTED),
            ExactMarkerState::InProgress
        );
        assert_eq!(
            exact_marker_state(b"corrupt marker\n", EXPECTED),
            ExactMarkerState::Mismatch
        );
        assert_eq!(
            exact_marker_state(b"complete marker\nextra", EXPECTED),
            ExactMarkerState::Mismatch
        );
    }
}

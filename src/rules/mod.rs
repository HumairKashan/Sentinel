mod auth;
mod brute;
mod sudo;

use crate::alert::Alert;
use crate::event::LogEvent;

pub struct Engine {
    brute_detector: brute::BruteForceDetector,
}

impl Engine {
    pub fn new(threshold: usize, window_secs: i64) -> Self {
        Self {
            brute_detector: brute::BruteForceDetector::new(threshold, window_secs),
        }
    }

    pub fn process(&mut self, ev: &LogEvent) -> Vec<Alert> {
        let mut alerts = Vec::new();

        // Run all detection rules
        if let Some(a) = auth::check_auth_failure(ev) {
            alerts.push(a);
        }

        if let Some(a) = auth::check_ssh_success(ev) {
            alerts.push(a);
        }

        if let Some(a) = sudo::check_sudo_usage(ev) {
            alerts.push(a);
        }

        // Brute force detector (stateful)
        if let Some(a) = self.brute_detector.check(ev) {
            alerts.push(a);
        }

        alerts
    }
}

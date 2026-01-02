use crate::alert::{Alert, Severity};
use crate::event::LogEvent;
use chrono::{DateTime, Duration, Local};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

pub struct BruteForceDetector {
    threshold: usize,
    window: Duration,
    // Track failures per IP
    failures: HashMap<IpAddr, VecDeque<DateTime<Local>>>,
    // Track which IPs we've already alerted on (to avoid spam)
    alerted: HashMap<IpAddr, DateTime<Local>>,
}

impl BruteForceDetector {
    pub fn new(threshold: usize, window_secs: i64) -> Self {
        Self {
            threshold,
            window: Duration::seconds(window_secs),
            failures: HashMap::new(),
            alerted: HashMap::new(),
        }
    }

    pub fn check(&mut self, ev: &LogEvent) -> Option<Alert> {
        // Only track auth failures
        let raw_lower = ev.raw.to_lowercase();
        if !raw_lower.contains("failed password") && !raw_lower.contains("authentication failure") {
            return None;
        }

        let ip = ev.ip?;
        let now = ev.ts.unwrap_or_else(Local::now);

        // Get or create the failure queue for this IP
        let queue = self.failures.entry(ip).or_insert_with(VecDeque::new);

        // Add this failure
        queue.push_back(now);

        // Remove failures outside the time window
        let cutoff = now - self.window;
        while let Some(&oldest) = queue.front() {
            if oldest < cutoff {
                queue.pop_front();
            } else {
                break;
            }
        }

        // Check if we've exceeded the threshold
        if queue.len() >= self.threshold {
            // Check if we've already alerted recently (within last 5 minutes)
            if let Some(&last_alert) = self.alerted.get(&ip) {
                if now - last_alert < Duration::minutes(5) {
                    return None; // Don't spam alerts
                }
            }

            // Record this alert
            self.alerted.insert(ip, now);

            return Some(Alert {
                rule_id: "brute_force",
                severity: Severity::High,
                ts: Some(now),
                ip: Some(ip),
                user: ev.user.clone(),
                message: format!(
                    "Possible brute-force attack: {} failures in {} seconds",
                    queue.len(),
                    self.window.num_seconds()
                ),
                raw: ev.raw.clone(),
            });
        }

        None
    }
}
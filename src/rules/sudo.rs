use crate::alert::{Alert, Severity};
use crate::event::LogEvent;
use chrono::Local;

pub fn check_sudo_usage(ev: &LogEvent) -> Option<Alert> {
    let raw = &ev.raw;

    // Look for sudo usage
    if raw.contains("sudo:") {
        let severity = if raw.to_lowercase().contains("authentication failure") {
            Severity::High
        } else if raw.contains("COMMAND=") {
            Severity::Low
        } else {
            Severity::Info
        };

        return Some(Alert {
            rule_id: "sudo_usage",
            severity,
            ts: ev.ts.or_else(|| Some(Local::now())),
            ip: ev.ip,
            user: ev.user.clone(),
            message: "Sudo command executed or attempted".to_string(),
            raw: ev.raw.clone(),
        });
    }
    None
}

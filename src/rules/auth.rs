use crate::alert::{Alert, Severity};
use crate::event::LogEvent;
use chrono::Local;

pub fn check_auth_failure(ev: &LogEvent) -> Option<Alert> {
    let raw_lower = ev.raw.to_lowercase();

    if raw_lower.contains("failed password") || raw_lower.contains("authentication failure") {
        return Some(Alert {
            rule_id: "auth_failure",
            severity: Severity::Medium,
            ts: ev.ts.or_else(|| Some(Local::now())),
            ip: ev.ip,
            user: ev.user.clone(),
            message: "Authentication failure detected".to_string(),
            raw: ev.raw.clone(),
        });
    }
    None
}

pub fn check_ssh_success(ev: &LogEvent) -> Option<Alert> {
    let raw_lower = ev.raw.to_lowercase();

    if raw_lower.contains("accepted password") || raw_lower.contains("accepted publickey") {
        return Some(Alert {
            rule_id: "ssh_success",
            severity: Severity::Info,
            ts: ev.ts.or_else(|| Some(Local::now())),
            ip: ev.ip,
            user: ev.user.clone(),
            message: "Successful SSH login".to_string(),
            raw: ev.raw.clone(),
        });
    }
    None
}
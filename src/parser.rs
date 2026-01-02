use crate::event::LogEvent;
use chrono::{DateTime, Local};
use regex::Regex;
use std::net::IpAddr;
use std::str::FromStr;

pub fn parse_line(line: &str) -> Option<LogEvent> {
    // Best-effort parsing:
    // - IP via regex
    // - user via simple patterns
    // - timestamp left as None for now (you can add later)

    let ip = extract_ip(line);
    let user = extract_user(line);

    Some(LogEvent {
        ts: extract_ts(line),
        ip,
        user,
        raw: line.to_string(),
    })
}

fn extract_ip(s: &str) -> Option<IpAddr> {
    // Simple IPv4/IPv6 capture
    let re = Regex::new(r"(?P<ip>(\d{1,3}\.){3}\d{1,3}|([0-9a-fA-F:]+:+)+[0-9a-fA-F]+)").ok()?;
    let cap = re.captures(s)?;
    let ip_str = cap.name("ip")?.as_str();
    IpAddr::from_str(ip_str).ok()
}

fn extract_user(s: &str) -> Option<String> {
    // Common patterns in auth logs:
    // "Failed password for <user>"
    // "Accepted password for <user>"
    // "for invalid user <user>"
    let patterns = [
        r"Failed password for (?P<u>\S+)",
        r"Accepted \w+ for (?P<u>\S+)",
        r"invalid user (?P<u>\S+)",
    ];

    for p in patterns {
        if let Ok(re) = Regex::new(p) {
            if let Some(cap) = re.captures(s) {
                if let Some(m) = cap.name("u") {
                    return Some(m.as_str().to_string());
                }
            }
        }
    }
    None
}

fn extract_ts(_s: &str) -> Option<DateTime<Local>> {
    // Keep it simple for v0.1: treat "now" for follow mode, None for batch is fine too.
    // If you want: parse "Jan  2 15:04:05" style later.
    None
}

use crate::event::LogEvent;
use chrono::{DateTime, Local, Datelike, TimeZone};
use regex::Regex;
use std::net::IpAddr;
use std::str::FromStr;

pub fn parse_line(line: &str) -> Option<LogEvent> {
    // Best-effort parsing:
    // - timestamp via syslog format
    // - IP via regex
    // - user via common patterns

    let ts = extract_ts(line);
    let ip = extract_ip(line);
    let user = extract_user(line);

    Some(LogEvent {
        ts,
        ip,
        user,
        raw: line.to_string(),
    })
}

fn extract_ip(s: &str) -> Option<IpAddr> {
    // Simple IPv4 capture - look for pattern like 192.168.1.100
    let ipv4_re = Regex::new(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").ok()?;
    if let Some(m) = ipv4_re.find(s) {
        if let Ok(ip) = IpAddr::from_str(m.as_str()) {
            return Some(ip);
        }
    }

    // Try IPv6 if IPv4 didn't match
    let ipv6_re = Regex::new(r"([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}").ok()?;
    if let Some(m) = ipv6_re.find(s) {
        if let Ok(ip) = IpAddr::from_str(m.as_str()) {
            return Some(ip);
        }
    }

    None
}

fn extract_user(s: &str) -> Option<String> {
    // Common patterns in auth logs:
    // "Failed password for <user>"
    // "Accepted password for <user>"
    // "for invalid user <user>"
    // "USER=<user>" (sudo logs - extracts target user, not invoker)
    let patterns = [
        r"Failed password for (?P<u>\S+)",
        r"Accepted \w+ for (?P<u>\S+)",
        r"invalid user (?P<u>\S+)",
        r"USER=(?P<u>\S+)",
        r"for (?P<u>\S+) from",
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

fn extract_ts(s: &str) -> Option<DateTime<Local>> {
    // Syslog style: "Jan  2 17:30:45" or "Jan 2 17:30:45"
    let re = Regex::new(
        r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<h>\d{2}):(?P<m>\d{2}):(?P<sec>\d{2})"
    ).ok()?;

    let cap = re.captures(s)?;

    let mon = match cap.name("mon")?.as_str() {
        "Jan" => 1, "Feb" => 2, "Mar" => 3, "Apr" => 4,
        "May" => 5, "Jun" => 6, "Jul" => 7, "Aug" => 8,
        "Sep" => 9, "Oct" => 10, "Nov" => 11, "Dec" => 12,
        _ => return None,
    };

    let day: u32 = cap.name("day")?.as_str().parse().ok()?;
    let h: u32 = cap.name("h")?.as_str().parse().ok()?;
    let m: u32 = cap.name("m")?.as_str().parse().ok()?;
    let sec: u32 = cap.name("sec")?.as_str().parse().ok()?;

    // Syslog doesn't include year, assume current year
    let year = Local::now().year();
    let nd = chrono::NaiveDate::from_ymd_opt(year, mon, day)?;
    let nt = chrono::NaiveTime::from_hms_opt(h, m, sec)?;
    let naive = chrono::NaiveDateTime::new(nd, nt);

    // Convert to local time, handling DST ambiguity properly
    Local.from_local_datetime(&naive).single()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Timelike;

    #[test]
    fn test_parse_auth_failure() {
        let line = "Jan  2 15:04:05 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2";
        let event = parse_line(line).unwrap();

        assert!(event.ts.is_some());
        assert_eq!(event.ip, Some("192.168.1.100".parse().unwrap()));
        assert_eq!(event.user, Some("admin".to_string()));
        assert!(event.raw.contains("Failed password"));
    }

    #[test]
    fn test_parse_ssh_success() {
        let line = "Jan  2 15:10:23 server sshd[5678]: Accepted publickey for alice from 10.0.0.50 port 54321 ssh2";
        let event = parse_line(line).unwrap();

        assert!(event.ts.is_some());
        assert_eq!(event.ip, Some("10.0.0.50".parse().unwrap()));
        assert_eq!(event.user, Some("alice".to_string()));
    }

    #[test]
    fn test_parse_sudo() {
        let line = "Jan  2 16:20:15 server sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow";
        let event = parse_line(line).unwrap();

        assert!(event.ts.is_some());
        // Note: extracts target user (root), not invoker (alice)
        assert_eq!(event.user, Some("root".to_string()));
        assert!(event.raw.contains("sudo"));
    }

    #[test]
    fn test_timestamp_parsing() {
        let line = "Jan  2 15:04:05 server message";
        let ts = extract_ts(line);

        assert!(ts.is_some());
        let dt = ts.unwrap();
        assert_eq!(dt.month(), 1);
        assert_eq!(dt.day(), 2);
        assert_eq!(dt.hour(), 15);
        assert_eq!(dt.minute(), 4);
        assert_eq!(dt.second(), 5);
    }

    #[test]
    fn test_ip_extraction() {
        let line = "Failed password from 192.168.1.100 port 22";
        let ip = extract_ip(line);
        assert_eq!(ip, Some("192.168.1.100".parse().unwrap()));
    }

    #[test]
    fn test_user_extraction_multiple_patterns() {
        let tests = vec![
            ("Failed password for admin from", "admin"),
            ("Accepted publickey for alice from", "alice"),
            ("invalid user hacker from", "hacker"),
            ("USER=root COMMAND=", "root"),
        ];

        for (line, expected) in tests {
            let user = extract_user(line);
            assert_eq!(user, Some(expected.to_string()));
        }
    }
}
use chrono::{DateTime, Local};
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct LogEvent {
    pub ts: Option<DateTime<Local>>,
    pub ip: Option<IpAddr>,
    pub user: Option<String>,
    pub raw: String,
}

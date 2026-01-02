use chrono::{DateTime, Local};
use serde::Serialize;
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub rule_id: &'static str,
    pub severity: Severity,
    pub ts: Option<DateTime<Local>>,
    pub ip: Option<IpAddr>,
    pub user: Option<String>,
    pub message: String,
    pub raw: String,
}

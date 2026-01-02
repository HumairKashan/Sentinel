use crate::alert::Alert;
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Default)]
pub struct Stats {
    pub by_rule: HashMap<&'static str, usize>,
    pub by_ip: HashMap<IpAddr, usize>,
}

impl Stats {
    pub fn observe(&mut self, a: &Alert) {
        *self.by_rule.entry(a.rule_id).or_insert(0) += 1;
        if let Some(ip) = a.ip {
            *self.by_ip.entry(ip).or_insert(0) += 1;
        }
    }
}

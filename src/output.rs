use crate::alert::Alert;
use crate::stats::Stats;
use anyhow::Result;

#[derive(Copy, Clone)]
pub enum OutputMode {
    Pretty,
    Jsonl,
}

pub fn print_alert(a: &Alert, mode: OutputMode) -> Result<()> {
    match mode {
        OutputMode::Pretty => {
            // Clean formatting: show actual values, not Some(...)
            let ip_str = match a.ip {
                Some(ip) => format!("ip={}", ip),
                None => String::new(),
            };

            let user_str = match &a.user {
                Some(u) => format!("user={}", u),
                None => String::new(),
            };

            // Build the info string, filtering out empty parts
            let info_parts: Vec<String> = vec![ip_str, user_str]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect();

            let info = if info_parts.is_empty() {
                String::new()
            } else {
                format!(" {} ::", info_parts.join(" "))
            };

            println!("[{:?}] {}{} {}", a.severity, a.rule_id, info, a.message);
        }
        OutputMode::Jsonl => {
            println!("{}", serde_json::to_string(a)?);
        }
    }
    Ok(())
}

pub fn print_summary(stats: &Stats) -> Result<()> {
    println!("\n== Summary ==");
    println!("By rule:");
    let mut rules: Vec<_> = stats.by_rule.iter().collect();
    rules.sort_by_key(|(_, v)| std::cmp::Reverse(**v));
    for (k, v) in rules {
        println!("  {k}: {v}");
    }

    println!("Top IPs:");
    let mut ips: Vec<_> = stats.by_ip.iter().collect();
    ips.sort_by_key(|(_, v)| std::cmp::Reverse(**v));
    for (ip, v) in ips.into_iter().take(5) {
        println!("  {ip}: {v}");
    }
    Ok(())
}
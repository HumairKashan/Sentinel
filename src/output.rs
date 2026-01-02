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
            println!(
                "[{:?}] {} ip={:?} user={:?} :: {}",
                a.severity, a.rule_id, a.ip, a.user, a.message
            );
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

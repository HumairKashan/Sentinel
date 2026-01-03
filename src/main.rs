mod alert;
mod cli;
mod event;
mod output;
mod parser;
mod reader;
mod rules;
mod stats;

use anyhow::Result;
use cli::Args;

use stats::Stats;

fn main() -> Result<()> {
    let args = Args::parse();

    let mut stats = Stats::default();
    let mut engine = rules::Engine::new(args.brute_threshold, args.brute_window_secs);
    let out_mode = if args.json {
        output::OutputMode::Jsonl
    } else {
        output::OutputMode::Pretty
    };

    let line_iter = reader::build_reader(&args)?;

    for line in line_iter {
        let line = line?;
        if let Some(ev) = parser::parse_line(&line) {
            let alerts = engine.process(&ev);
            for alert in alerts {
                stats.observe(&alert);
                output::print_alert(&alert, out_mode)?;
            }
        }
    }

    if args.summary {
        output::print_summary(&stats)?;
    }

    Ok(())
}

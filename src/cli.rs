use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "rust-log-sentinel", version, about = "Lightweight log monitoring + alerting")]
pub struct Args {
    /// Path to a log file (e.g., /var/log/auth.log)
    #[arg(long)]
    pub file: Option<String>,

    /// Read from stdin
    #[arg(long)]
    pub stdin: bool,

    /// Follow the file like tail -f
    #[arg(long)]
    pub follow: bool,

    /// Output alerts as JSON Lines
    #[arg(long)]
    pub json: bool,

    /// Print summary at the end
    #[arg(long)]
    pub summary: bool,

    /// Brute-force threshold (failures in window)
    #[arg(long, default_value_t = 8)]
    pub brute_threshold: usize,

    /// Brute-force window in seconds
    #[arg(long, default_value_t = 60)]
    pub brute_window_secs: i64,
}

impl Args {
    pub fn parse() -> Self {
        <Self as clap::Parser>::parse()
    }
}

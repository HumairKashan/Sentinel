# Sentinel

Sentinel is a lightweight Rust-based log analysis and intrusion detection tool
designed to detect authentication failures, brute-force attacks, and privileged
command usage from system logs.

## Features
- SSH authentication failure detection
- Brute-force attack detection using sliding windows
- Successful SSH login tracking
- Sudo usage monitoring
- Pretty and JSONL output modes
- Summary statistics by rule and IP

## Usage
```bash
cargo run -- --file samples/auth_sample.log --summary
cargo run -- --file samples/auth_sample.log --json

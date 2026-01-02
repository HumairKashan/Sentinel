# 🛡️ Sentinel

A fast, lightweight CLI log monitoring and alerting tool written in Rust. Sentinel watches log files in real-time, detects suspicious patterns, and alerts you to potential security issues.

## ✨ Features

- **Real-time monitoring** - Follow logs with `tail -f` style live updates
- **Smart detection** - Built-in rules for common security patterns:
  - Authentication failures (SSH, sudo, etc.)
  - Brute-force attack detection with sliding time windows
  - Sudo command monitoring
  - Successful SSH logins
- **Flexible input** - Read from files, stdin, or follow mode
- **Multiple output formats** - Human-readable colored output or JSON Lines for automation
- **Statistical summaries** - Aggregated stats by rule, IP, and user
- **Fast & efficient** - Written in Rust for maximum performance

## 🚀 Installation

### From Source

```bash
git clone https://github.com/HumairKashan/Sentinel.git
cd Sentinel
cargo build --release
```

The binary will be at `target/release/Sentinel`

### Using Cargo

```bash
cargo install --path .
```

## 📖 Usage

### Basic Commands

```bash
# Monitor a log file
sentinel --file /var/log/auth.log

# Follow a log file in real-time (like tail -f)
sentinel --file /var/log/auth.log --follow

# Read from stdin (pipe logs in)
journalctl -u ssh | sentinel --stdin

# Output as JSON Lines for automation
sentinel --file /var/log/auth.log --json

# Show summary statistics at the end
sentinel --file /var/log/auth.log --summary
```

### Advanced Usage

```bash
# Customize brute-force detection thresholds
sentinel --file /var/log/auth.log \
  --brute-threshold 5 \
  --brute-window-secs 30

# Monitor SSH logs in real-time with JSON output
tail -f /var/log/auth.log | sentinel --stdin --json
```

## 🔍 Detection Rules

Sentinel includes the following built-in detection rules:

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `auth_failure` | Medium | Detects failed password attempts and authentication failures |
| `ssh_success` | Info | Logs successful SSH logins |
| `sudo_usage` | Low-High | Monitors sudo command execution and failures |
| `brute_force` | High | Identifies potential brute-force attacks using sliding time windows |

### Brute-Force Detection

The brute-force detector uses a sliding time window to identify rapid authentication failures from the same IP address:

- Default: 8 failures within 60 seconds triggers an alert
- Customizable via `--brute-threshold` and `--brute-window-secs`
- Prevents alert spam with a 5-minute cooldown per IP

## 📊 Example Output

### Pretty Output (Default)

```
[Medium] auth_failure ip=Some(192.168.1.100) user=Some("admin") :: Authentication failure detected
[Medium] auth_failure ip=Some(192.168.1.100) user=Some("root") :: Authentication failure detected
[High] brute_force ip=Some(192.168.1.100) user=Some("admin") :: Possible brute-force attack: 8 failures in 60 seconds
[Info] ssh_success ip=Some(10.0.0.50) user=Some("alice") :: Successful SSH login

== Summary ==
By rule:
  auth_failure: 12
  brute_force: 1
  ssh_success: 3
Top IPs:
  192.168.1.100: 8
  10.0.0.50: 3
```

### JSON Output

```json
{"rule_id":"auth_failure","severity":"Medium","ts":"2026-01-02T17:30:45+04:00","ip":"192.168.1.100","user":"admin","message":"Authentication failure detected","raw":"Jan  2 17:30:45 server sshd[1234]: Failed password for admin from 192.168.1.100"}
{"rule_id":"brute_force","severity":"High","ts":"2026-01-02T17:31:15+04:00","ip":"192.168.1.100","user":"admin","message":"Possible brute-force attack: 8 failures in 60 seconds","raw":"..."}
```

## 🏗️ Architecture

```
src/
├── main.rs           # Entry point and orchestration
├── cli.rs            # Command-line argument parsing (clap)
├── reader.rs         # File/stdin reading with follow mode
├── parser.rs         # Log line parsing (IP, user, timestamp extraction)
├── event.rs          # LogEvent data structure
├── rules/
│   ├── mod.rs        # Detection engine
│   ├── auth.rs       # Authentication detection rules
│   ├── sudo.rs       # Sudo monitoring rules
│   └── brute.rs      # Brute-force detection with sliding windows
├── alert.rs          # Alert data structure
├── output.rs         # Output formatting (pretty/JSON)
└── stats.rs          # Statistics aggregation
```

## 🔧 Configuration

Create a `rules.yaml` file for custom detection patterns (future feature):

```yaml
custom_rules:
  - name: suspicious_user_agent
    pattern: "curl|wget|python"
    severity: medium
    message: "Suspicious user agent detected"
```

## 🛠️ Development

### Requirements

- Rust 1.70+ (edition 2021)
- Cargo

### Building

```bash
cargo build
```

### Running Tests

```bash
cargo test
```

### Linting

```bash
cargo clippy
```

## 📝 Roadmap

- [ ] YAML-based custom rule definitions
- [ ] Support for more log formats (nginx, Apache, syslog)
- [ ] Real-time alerting (webhook, email, Slack)
- [ ] Dashboard/web UI
- [ ] GeoIP lookup for suspicious IPs
- [ ] Machine learning-based anomaly detection
- [ ] Performance metrics and benchmarking

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [Rust](https://www.rust-lang.org/)
- Inspired by traditional SIEM tools and security monitoring needs
- Part of my security tooling portfolio alongside [Network Intrusion Detection System](https://github.com/HumairKashan/NIDS)

## 📧 Contact

**Humair Kashan** - [@HumairKashan](https://github.com/HumairKashan)

Project Link: [https://github.com/HumairKashan/Sentinel](https://github.com/HumairKashan/Sentinel)

---

⭐ If you find this project useful, please consider giving it a star on GitHub!

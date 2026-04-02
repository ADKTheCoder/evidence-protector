<div align="center">

<pre>
███████╗██╗   ██╗██╗██████╗ ███████╗███╗   ██╗ ██████╗███████╗
██╔════╝██║   ██║██║██╔══██╗██╔════╝████╗  ██║██╔════╝██╔════╝
█████╗  ██║   ██║██║██║  ██║█████╗  ██╔██╗ ██║██║     █████╗  
██╔══╝  ╚██╗ ██╔╝██║██║  ██║██╔══╝  ██║╚██╗██║██║     ██╔══╝  
███████╗ ╚████╔╝ ██║██████╔╝███████╗██║ ╚████║╚██████╗███████╗
╚══════╝  ╚═══╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚══════╝
                    P R O T E C T O R
</pre>

**Detect tampering. Preserve evidence. Trust your logs.**

![Python](https://img.shields.io/badge/Python-3.6+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)
![Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

</div>

## What is Evidence Protector?

In cybersecurity, **missing logs are as suspicious as the logs themselves.**

When an attacker compromises a system, one of their first moves is to wipe or tamper with log files to erase their tracks. Evidence Protector is a forensics-grade CLI tool that scans log files for **suspicious time gaps** — periods where no events were recorded — and classifies them by severity.

Built for Security Operations (SecOps) teams, digital forensics investigators, and IT auditors who need a fast, zero-dependency tool that runs anywhere Python runs.

---

## Features

| | Feature |
|---|---|
| 🔍 | Detects suspicious time gaps in log files |
| ⚠️ | Classifies severity: `LOW` / `MEDIUM` / `HIGH` |
| 📊 | Generates detailed forensic terminal report |
| 📁 | Auto-exports full evidence to `gaps_report.csv` |
| 🧠 | Smart triage — shows most critical gaps first |
| 🔧 | Configurable threshold via `--threshold` flag |
| 💡 | Fully commented, beginner-friendly codebase |
| 🐍 | Zero dependencies — Python stdlib only |
| ⚡ | Memory-efficient O(1) line-by-line processing |
| 🖥️ | Cross-platform: Linux, macOS, Windows |

---

## Demo
```
$ python3 integrity_check.py sample_large.log --threshold 60

*** Evidence Protector - Automated Log Integrity Monitor ***

======================================================================
 FORENSIC REPORT: LOG INTEGRITY ANALYSIS
======================================================================
 EXECUTION INFO:
  - Log File         : sample_large.log
  - Config Threshold : 60 seconds
  - Lines Processed  : 312
  - Execution Time   : 0.0021 seconds
----------------------------------------------------------------------
 Gap #1 Detected [!! HIGH !!]
   Start Time : 2024-03-26 08:21:37
   End Time   : 2024-03-26 10:19:37
   Duration   : 7080 seconds
   Why this is suspicious:
     This gap exceeds the configured baseline threshold, suggesting
     potential log tampering (wiped tracks) or an unlogged system outage.
   Action     :
     Correlate this missing time window with external system metrics,
     network traffic logs, or secondary audit trails to determine root cause.
----------------------------------------------------------------------
   ...and 11 more gaps not shown (use --display all to view all)

======================================================================
 SUMMARY AND INTERPRETATION
======================================================================
 Total Gaps Found : 12
 Lines Skipped    : 23 (noise, malformed, or missing timestamps)
 Gaps by Severity :
   - HIGH         : 5
   - MEDIUM       : 4
   - LOW          : 3

[✓] CSV report saved → gaps_report.csv
```

---

## Installation
```bash
# 1. Clone the repository
git clone https://github.com/ADKTheCoder/evidence-protector.git
cd evidence-protector

# 2. No installation needed — zero dependencies
# Just run it directly with Python 3.6+
python3 integrity_check.py --help
```

---

## Usage

### Basic Commands
```bash
# Analyze a log file (default threshold: 300s, shows top 5 gaps)
python3 integrity_check.py sample.log

# Custom threshold — flag gaps larger than 60 seconds
python3 integrity_check.py sample.log --threshold 60

# Show top 10 gaps instead of 5
python3 integrity_check.py sample.log --threshold 60 --display 10

# Show every detected gap
python3 integrity_check.py sample.log --threshold 60 --display all

# Run in demo/presentation mode
python3 integrity_check.py sample.log --demo
```

### CLI Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `logfile` | positional | required | Path to the log file to analyze |
| `--threshold` | int | `300` | Gap size in seconds before triggering an alert |
| `--display` | choice | `5` | Gaps to show: `5`, `10`, or `all` |
| `--time-format` | str | `%y%m%d %H%M%S` | Timestamp format of the log file |
| `--demo` | flag | off | Enables presentation mode with delays |

---

## How It Works
```
┌──────────────┐     ┌──────────────┐     ┌───────────────┐
│  Log File    │────▶│ Input Layer  │────▶│ Parsing Layer │
│ (any source) │     │ Generator    │     │ Timestamps    │
└──────────────┘     │ O(1) memory  │     │ → datetime    │
                     └──────────────┘     └──────┬────────┘
                                                 │
                          ┌──────────────────────▼──────────────┐
                          │         Detection Engine             │
                          │  Compare t vs t-1 → flag if > gap   │
                          │  Calculate severity (LOW/MED/HIGH)   │
                          └──────────────────┬──────────────────┘
                                             │
                          ┌──────────────────▼──────────────────┐
                          │         Reporting Layer              │
                          │  Sort by severity → Terminal report  │
                          │  Export 100% of evidence to CSV      │
                          └─────────────────────────────────────┘
```

### Severity Classification

| Severity | Condition | Meaning |
|----------|-----------|---------|
| `LOW` | gap ≤ 2× threshold | Minor anomaly, worth noting |
| `MEDIUM` | gap > 2× and ≤ 5× threshold | Moderate concern, investigate |
| `HIGH` | gap > 5× threshold | Critical — immediate review required |

---

## Input Format

The tool expects timestamps at the start of each line:
```
YYMMDD HHMMSS [LEVEL] Component: Message
240326 203000 [INFO]  System started normally
240326 203100 [WARN]  Disk usage at 78%
240326 212000 [INFO]  Backup initiated       ← gap detected here
```

Custom formats supported via `--time-format` flag.

---

## Project Structure
```
evidence-protector/
├── integrity_check.py    ← Main CLI tool (all logic lives here)
├── sample.log            ← Small demo log with intentional gaps
├── sample_large.log      ← Large demo log (300+ lines, 12+ gaps)
├── ARCHITECTURE.md       ← Technical design decisions
├── DESIGN.md             ← UX and output design rationale
├── requirements.txt      ← No external dependencies
├── LICENSE               ← MIT
└── README.md
```

---

## Use Cases

| Who | How they use it |
|-----|----------------|
| Security Analysts | Detect log tampering during incident response |
| Digital Forensics Teams | Validate log continuity as legal evidence |
| IT Administrators | Audit logging daemon health and uptime |
| Compliance Officers | Verify log integrity for regulatory audits |
| CTF Players / Students | Learn log forensics hands-on |

---

## Design Decisions

Two documents explain the thinking behind the tool:

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — how the 4-layer pipeline works, memory strategy, and error handling
- **[DESIGN.md](DESIGN.md)** — why triage-first output matters, tradeoffs made, and workflow fit

---

## Contributing

Pull requests are welcome. For major changes, open an issue first.

1. Fork the repo
2. Create your branch: `git checkout -b feature/your-feature`
3. Commit: `git commit -m "Add your feature"`
4. Push: `git push origin feature/your-feature`
5. Open a Pull Request

---

## License

MIT © [Aditya Khanna](https://github.com/ADKTheCoder)

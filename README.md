# Evidence Protector - Automated Log Integrity Monitor

## Overview
Evidence Protector is a lightweight, high-performance forensic analysis tool designed for Security Operations (SecOps) teams. It sequentially scans computer log files memory-efficiently to detect anomalous time gaps. In cybersecurity analysis, missing logs are a massive red flag, indicating potential adversarial log wiping, tracking evasion, or unlogged critical service failures. 

## Features
- **Zero Dependencies**: Relies entirely on native Python 3 standard libraries for immediate portability across systems without `pip install`.
- **Memory Efficiency**: Utilizes O(1) memory generators, allowing processing of massive multi-gigabyte forensic logs without crashing.
- **Smart Triage**: Automatically sorts detected gaps by severity (HIGH > MEDIUM > LOW) and duration.
- **Analyst Focus**: Defaults to displaying only the top 5 most critical events to prevent alert fatigue.
- **Flexible Scope**: Custom view limits via `--top N` and `--show-all` flags, while unconditionally exporting 100% of the evidence to CSV.
- **Resilient**: Gracefully skips corrupted or missing timestamps injected via adversarial tampering rather than crashing.
- **Configurable**: Highly customizable thresholds and tunable timestamp parsers for compatibility with different environments.
- **Analyst-Ready**: Outputs clear contextual forensic reports with calculated severities, interpretations, and automatic CSV structured evidence exports (`gaps_report.csv`).

## Requirements
- Python 3.6+
- No external libraries required.

## How to Run

1. Open your terminal.
2. Ensure you have your target log file in the same directory (e.g., `sample.log`).
3. Execute the script via Python:

### Example Commands
```bash
# Default Analysis (Shows top 5 gaps)
python3 integrity_check.py sample.log --threshold 60

# Custom Analysis (Shows top 10 criticality gaps)
python3 integrity_check.py sample.log --threshold 60 --display 10

# Full Analysis (Displays all detected gaps)
python3 integrity_check.py sample.log --threshold 60 --display all
```

### Advanced Usage & CLI Arguments
- `logfile` (Required): The path to the log file to analyze.
- `--threshold` (Optional): Time gap threshold in seconds before an alert is triggered (Default is 300).
- `--display` (Optional): Amount of evidence to display (`5`, `10`, or `all`). (Default is `5`).
- `--time-format` (Optional): Configure parser for different log timestamps (Default is `%y%m%d %H%M%S`).
- `--demo` (Optional): Enables presentation flair formatting.

## Input Format
The tool defaults to expecting timestamps at the beginning of the line in the format `%y%m%d %H%M%S` (e.g., `240326 203000 [INFO] User logged in`). However, you can configure it dynamically.

## Output Explanation
Evidence protector displays clear text-based forensics mapping to standard SIEM outputs.
- **Execution Info**: Run time metrics and parameters processed.
- **Categorical Alerts**: Details the specific Start/End times of dropped timeframes.
- **Analyst Interpretation**: Explains why the alert matters and suggests exact steps for incident response.
- **CSV Data Dump**: Generates `gaps_report.csv` natively for auditing requirements.

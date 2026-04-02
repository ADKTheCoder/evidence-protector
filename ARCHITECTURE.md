# Architecture: Evidence Protector

## Module Breakdown

The system relies on an intensely modular pipeline architecture separated by functional concern. This ensures that independent pieces of logic can be swapped out without destroying the core algorithm.

### 1. Input Layer (`read_log_lines`)
Responsible for reading target log files. It utilizes Python `generators`, creating an asynchronous pipeline yielding single strings (lines) to preserve memory footprint (`O(1)` memory overhead). 

### 2. Parsing Layer (`parse_timestamp`)
Ingests raw lines and structures them into workable data objects. It calculates native offsets and safely unpacks string timestamps to `datetime` objects. It is fully separated so it can be overwritten for completely different schemas (e.g., JSON parsers) without changing `detect_gaps`.

### 3. Detection Engine (`detect_gaps` & `calculate_severity`)
The core processing brain. Utilizing State pattern via `previous_time` memory tracking, it compares chronological drift. It utilizes proportional mathematical scaling to calculate impact Severity (LOW, MEDIUM, HIGH) compared to the user's expected noise boundary (the Threshold).

### 4. Reporting Layer (`generate_report` & `export_csv`)
Translates programmatic lists and dictionaries into human-centric, presentation-ready metrics. It features:
- **Sorting Mechanism**: Arrays are sorted using a multi-key lambda function. Priority 1 is `Severity` (HIGH > MEDIUM > LOW). Priority 2 is the `Duration` of the gap in descending order.
- **Output Control System**: Implements a strict, configurable truncation system (`--display 5`, `10`, or `all`) that defaults to displaying only the top 5 anomalies.

This limitation is critical because dumping massive amounts of evidence to a terminal window causes information overload and analyst fatigue. However, while the console output is limited for usability, the `export_csv` function unconditionally receives the entire dataset to maintain strict compliance auditing.

## Data Flow
The data flow travels linearly and predictably:
**Log** (Disk) -> **Yield** (Input) -> **String -> Datetime** (Parse) -> **Delta Computation** (Detect) -> **Console & Fileout** (Report)

## Error Handling Strategy
- **Antifragile Processing**: Security tools are attacked tools. Thus, the Parsing Engine embraces failures (returning `None`) instead of throwing exceptions on corrupted or intentionally mangled lines.
- **Clean IO Validation**: Native operating system exceptions (like `FileNotFoundError`) are gracefully intercepted before traceback occurs, rendering them to the user via STDERR, maintaining trust and interface integrity.

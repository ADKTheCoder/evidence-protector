import sys
import csv
import argparse
import time
from datetime import datetime
from collections import Counter

# ===========================================================================
# Evidence Protector - Automated Log Integrity Monitor
# 
# Purpose: This system acts as a digital forensic investigator. It reads through
# computer log files and looks for "chunks of missing time" (gaps) that shouldn't
# be there. In cybersecurity, missing logs usually mean an attacker deleted their
# tracks or a critical system went offline without recording the crash.
# 
# Architecture: We use a modular design separated into four independent layers:
# 1. Input Layer (reads files safely and efficiently)
# 2. Parsing Layer (extracts dates and times)
# 3. Detection Engine (the core "brain" finding the gaps)
# 4. Reporting Layer (creates human-readable alerts and CSVs)
# 
# DESIGN DECISION (Modular Design):
# By keeping these layers separate, we can easily upgrade one piece—like changing
# the tool to read JSON logs instead of plain text—without rewriting the core math.
# ===========================================================================

# ---------------------------------------------------------------------------
# GLOBAL ERROR HANDLING
# ---------------------------------------------------------------------------
class LogProcessingError(Exception):
    """Custom exception used to handle specific errors gracefully instead of crashing."""
    pass

# ===========================================================================
# 1. INPUT LAYER
# ===========================================================================
def read_log_lines(filepath):
    """
    Function: read_log_lines
    Reads log files memory-efficiently, one single line at a time.
    
    DESIGN DECISION (Memory Efficiency):
    Real-world server logs can be massive (gigabytes across millions of lines). 
    If we tried to load the entire file into the computer's memory (RAM) at once, 
    the program would crash. Instead, we use a Python "generator" (the 'yield' keyword)
    to read exactly one line, process it, and then throw it away before reading the next.
    """
    try:
        # Open the file for reading in text mode.
        with open(filepath, 'r', encoding='utf-8') as f:
            # Loop through the file line by line
            for line in f:
                # 'yield' sends one line to the Detection Engine and waits until it asks for the next
                yield line
                
    except FileNotFoundError:
        # If the file doesn't exist, we alert the user instead of breaking ugly.
        print(f"Error: Log file not found at '{filepath}'. Please check the path and try again.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        # Catch any unexpected errors (like permission denied)
        print(f"Error reading file {filepath}: {e}", file=sys.stderr)
        sys.exit(1)

# ===========================================================================
# 2. PARSING LAYER
# ===========================================================================
def parse_timestamp(line, time_format):
    """
    Function: parse_timestamp
    Extracts the timestamp from a raw line of text so the computer understands it as a date.
    
    In cybersecurity, logs come in hundreds of different formats. This function
    is designed to be easily swappable if an organization uses a different time format.
    """
    # First, figure out exactly how many characters long the timestamp should be.
    # For example, "240326 203000" is 13 characters.
    expected_length = len(datetime.now().strftime(time_format))
    
    # If the line is shorter than a normal timestamp, it's malformed.
    if len(line) < expected_length:
        return None
        
    # Slice the timestamp string directly out from the beginning of the line
    time_str = line[:expected_length]
    try:
        # Convert the raw text string into a Python "datetime" object that natively supports math
        return datetime.strptime(time_str, time_format)
    except ValueError:
        # If the text isn't a date (e.g., random noise or corrupted file), we return None
        return None

# ===========================================================================
# 3. DETECTION ENGINE
# ===========================================================================
def calculate_severity(duration, threshold):
    """
    Function: calculate_severity
    Given a suspicious gap of time, how bad is it? We dynamically scale the danger.
    """
    # If the gap is less than double the allowed threshold, it's a minor LOW severity issue.
    if duration <= threshold * 2:
        return "LOW"
    # If the gap is up to 5 times the limit, it gets a MEDIUM warning.
    elif duration <= threshold * 5:
        return "MEDIUM"
    # If the gap exceeds 5 times the normal limit, it's HIGH priority for immediate review.
    else:
        return "HIGH"

def detect_gaps(log_lines, threshold, time_format, demo_mode=False):
    """
    Function: detect_gaps
    The core logic of the program. It compares every line against the one right before it.
    
    DESIGN DECISION (Configurable Threshold):
    Every company's servers are different. A quiet database might normally log something 
    once an hour, but a busy web server logs hundreds of times a second. By making the 
    threshold configurable, we prevent alert fatigue (thousands of false alarms).
    
    DESIGN DECISION (Skipping Bad Lines):
    Cyber attackers sometimes try to break forensics tools by injecting corrupted garbage 
    text into the log. If our tool crashed upon seeing garbage, the attacker would win. 
    Instead, we safely skip bad lines and keep monitoring.
    """
    # Keep track of the timestamp we saw on the previous valid line
    previous_time = None
    # A list to store any suspicious gaps we find
    gaps = []
    
    skipped_lines = 0
    total_lines = 0
    
    # Optional presentation mode to look professional on stage
    if demo_mode:
        print("[*] Processing...", flush=True)
        time.sleep(1)
        
    # We step through the log, keeping track of the line number
    for line_num, line in enumerate(log_lines, 1):
        total_lines = line_num
        
        # Ask the Parsing Layer to translate this line into a valid date
        current_time = parse_timestamp(line, time_format)
        
        # If the parsing layer couldn't read the date, we skip it safely
        if not current_time:
            skipped_lines += 1
            continue
            
        # If we have a previous time to compare against, do the math
        if previous_time is not None:
            # Calculate the total seconds that passed between the last log and this log
            delta = (current_time - previous_time).total_seconds()
            
            # CORE LOGIC: Is this amount of missing time suspicious?
            # If the missing time is greater than our defined limit (threshold)
            if delta > threshold:
                # We caught an anomaly! Save it for the final report.
                gaps.append({
                    'start_time': previous_time,
                    'end_time': current_time,
                    'duration': delta,
                    'severity': calculate_severity(delta, threshold)
                })
                
        # Update our tracker so the "current" time becomes the "previous" time for the next loop
        previous_time = current_time
        
    return gaps, skipped_lines, total_lines

# ===========================================================================
# 4. REPORTING LAYER
# ===========================================================================
def export_csv(gaps, export_path="gaps_report.csv"):
    """
    Function: export_csv
    SecOps (Security Operations) teams don't just read screens; they need raw data
    to feed into tools like Splunk. This automatically builds a CSV evidence file.
    """
    if not gaps:
        return
        
    try:
        # Open a new spreadsheet file for writing
        with open(export_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['start_time', 'end_time', 'duration', 'severity']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            # Write the column headers
            writer.writeheader()
            
            # Write each gap's data as a row in the spreadsheet
            for gap in gaps:
                writer.writerow({
                    'start_time': gap['start_time'].strftime('%Y-%m-%d %H:%M:%S'),
                    'end_time': gap['end_time'].strftime('%Y-%m-%d %H:%M:%S'),
                    'duration': int(gap['duration']),
                    'severity': gap['severity']
                })
        print(f"\n[INFO] CSV report successfully saved to {export_path}")
    except Exception as e:
        print(f"Error saving CSV file: {e}", file=sys.stderr)

def generate_report(gaps, skipped_lines, total_lines, logfile, threshold, elapsed_time, display_mode, demo_mode=False):
    """
    Function: generate_report
    Translates raw computer data into a clear, actionable summary for humans.
    It builds trust by being transparent about its assumptions and logic.
    """
    if demo_mode:
        print("[*] Generating report...", flush=True)
        time.sleep(0.5)
        
    print("\n" + "="*70)
    print(" FORENSIC REPORT: LOG INTEGRITY ANALYSIS")
    print("="*70)
    
    # Show high-level metrics so the analyst knows the context
    print(" EXECUTION INFO:")
    print(f"  - Log File         : {logfile}")
    print(f"  - Config Threshold : {threshold} seconds")
    print(f"  - Lines Processed  : {total_lines}")
    print(f"  - Execution Time   : {elapsed_time:.4f} seconds")
    print("-" * 70)
    
    # If the system found nothing wrong, tell the user explicitly
    if not gaps:
        print(" [OK] No suspicious gaps detected. Log integrity appears intact.")
        print(f" [!] Skipped {skipped_lines} unparseable lines.")
        print("="*70)
        return

    # Count how many HIGH, MEDIUM, and LOW alerts we generated based on all gaps
    severity_counts = Counter(gap['severity'] for gap in gaps)
    
    # -----------------------------------------------------------------------
    # SORTING AND FILTERING LOGIC
    # -----------------------------------------------------------------------
    # We assign numerical weights to severities to accurately sort them
    severity_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    
    # DESIGN DECISION (Sorting Constraints):
    # During a massive breach, analysts need to triage the most dangerous events first.
    # We sort all evidence first by Severity (HIGH to LOW), then by Duration (Longest to Shortest).
    sorted_gaps = sorted(gaps, key=lambda x: (severity_rank.get(x['severity'], 0), x['duration']), reverse=True)
    
    # DESIGN DECISION (Display Limiting):
    # Alert fatigue is real. Dumping 1,000 logs into a terminal renders it useless.
    # By default, we only show the top N critical gaps for a quick operational
    # overview, while STILL exporting 100% of the evidence to the CSV file.
    if display_mode == "all":
        display_gaps = sorted_gaps
    else:
        top_n = int(display_mode)
        display_gaps = sorted_gaps[:top_n]
        
    hidden_gaps = len(sorted_gaps) - len(display_gaps)

    # Formatting loop: Present each filtered piece of evidence
    for i, gap in enumerate(display_gaps, 1):
        sev_tag = gap['severity']
        
        # Add visual emphasis for critical alerts
        if sev_tag == "HIGH":
            sev_tag = "[!! HIGH !!]"
        else:
            sev_tag = f"({sev_tag})"
            
        print(f" Gap #{i} Detected {sev_tag}")
        print(f"   Start Time : {gap['start_time'].strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"   End Time   : {gap['end_time'].strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"   Duration   : {int(gap['duration'])} seconds")
        
        # Explain the 'why' - crucial for junior analysts
        print("   Why this is suspicious:")
        print("     This gap exceeds the configured baseline threshold, suggesting")
        print("     potential log tampering (wiped tracks) or an unlogged system outage.")
        
        # Provide an actionable next step
        print("   Action     :")
        print("     Correlate this missing time window with external system metrics,")
        print("     network traffic logs, or secondary audit trails to determine root cause.")
        print("-" * 70)
        
    if hidden_gaps > 0:
        print(f"   ...and {hidden_gaps} more gaps not shown (use --display all to view all)")
        print("-" * 70)
        
    # The Executive Summary
    print("\n" + "="*70)
    print(" SUMMARY AND INTERPRETATION")
    print("="*70)
    print(f" Total Gaps Found : {len(gaps)}")
    print(f" Lines Skipped    : {skipped_lines} (noise, malformed, or missing timestamps)")
    print(" Gaps by Severity :")
    print(f"   - HIGH         : {severity_counts.get('HIGH', 0)}")
    print(f"   - MEDIUM       : {severity_counts.get('MEDIUM', 0)}")
    print(f"   - LOW          : {severity_counts.get('LOW', 0)}\n")
    
    # Teach the user how to read the results
    print(" INTERPRETATION:")
    print(" - Review HIGH severity gaps immediately, as they indicate significant")
    print("   missing time ranges.")
    print(" - Investigate MEDIUM/LOW gaps if they correlate with known incident")
    print("   windows.\n")
    
    # Disclaim assumptions
    print(" [CONFIDENCE NOTE]")
    print(" Detection is based purely on threshold-based temporal anomaly detection.")
    print(" Results are highly dependent on the configured baseline threshold.\n")
    
    # Reduce false positive panic
    print(" [FALSE POSITIVE WARNING]")
    print(" Some gaps may be completely valid due to normal system idle periods,")
    print(" maintenance windows, or known expected service restarts.")
    print("="*70)
    
    # Run the CSV export function implicitly using ALL sorted gaps
    export_csv(sorted_gaps)

# ===========================================================================
# 5. MAIN EXECUTION START
# ===========================================================================
def main():
    """
    Function: main
    The entry point of the program. It parses the instructions the user typed in 
    the command line, and orchestrates the Input, Parsing, Detection, and Reporting layers.
    """
    # Argparse prepares the tool to receive commands effectively
    parser = argparse.ArgumentParser(description="Evidence Protector: Automated Log Integrity Monitor")
    parser.add_argument("logfile", help="Path to the log file to analyze")
    parser.add_argument("--threshold", type=int, default=300, help="Time gap threshold in seconds")
    parser.add_argument("--time-format", type=str, default="%y%m%d %H%M%S", help="Timestamp format string")
    parser.add_argument("--display", choices=["5", "10", "all"], default="5", help="Amount of evidence to display (choices: 5, 10, all; default: 5)")
    parser.add_argument("--demo", action="store_true", help="Run in presentation demo mode")
    args = parser.parse_args()
    
    print("\n*** Evidence Protector - Automated Log Integrity Monitor ***")
    
    # Optional presentation flair
    if args.demo:
        print("[*] Analyzing log file...", flush=True)
        time.sleep(0.5)
        
    # Start a stopwatch to measure how fast our tool is
    start_time = time.time()
    
    # Step 1: Open the log file (Input Layer)
    log_lines = read_log_lines(args.logfile)
    
    # Step 2 & 3: Find the gaps inside those lines (Parsing & Detection layers)
    gaps, skipped_lines, total_lines = detect_gaps(log_lines, args.threshold, args.time_format, args.demo)
    
    # Stop the stopwatch
    elapsed_time = time.time() - start_time
    
    # Step 4: Show the final analytical results (Reporting layer)
    generate_report(gaps, skipped_lines, total_lines, args.logfile, args.threshold, elapsed_time, args.display, args.demo)

# This standard Python convention ensures that if another script decides to 
# import our code, it doesn't accidentally run the main() function immediately.
if __name__ == "__main__":
    main()

# Design Rationale: Evidence Protector

## Output Design Strategy
Security Operations analysts operate under intense time constraints during active incidents. Translating hundreds of results natively into a terminal window paralyzes analysis through sheer information overload. 

Therefore, Evidence Protector adopts an aggressive **Triage-First** approach:
- By default, it exclusively shows the **top 5** most highly-ranked critical gaps.
- It calculates this urgency reliably via a dual-weight sort (Severity -> Duration).
- Users can manually expand the context window using the precise `--display` choice modifier (`5`, `10`, or `all`).

### Tradeoff: Completeness vs Usability
This introduces a known tradeoff between immediate visual *completeness* (showing all data) and *usability* (showing critical insights first). 
We resolve this conflict by ensuring the **CSV Export** unconditionally retains 100% of the discovered anomalies. This ensures zero data is lost for deep forensics, while the **CLI Controls** guarantee immediate operational flexibility during live investigations.

## Other Tradeoffs
Evidence Protector embraces specific technical constraints in favor of reliability. 
- **Simplicity vs. Complexity**: By avoiding heavy AI, ML profiling, or probabilistic graph modeling, the system achieves maximum robustness. It runs deterministically, incredibly fast across billions of lines, and produces 100% explainable metrics avoiding stochastic "black box" false positives.
- **Generators vs Memory Mapping**: Reading line-by-line prevents complex lookarounds, but makes processing essentially infinite in size limit compared to standard memory allocation. 

## Simplifications
- **Chronological Logs**: The system simplifies the state management by inherently assuming logs are written chronologically. It compares strictly `t-1 vs t`. It will not actively sort randomized unstructured ingestion dumps prior to threshold analysis.

## User Value
For Security Engineers and Analysts dealing with intense active incident response investigations, analyzing millions of log lines is like finding a needle in a haystack. Evidence Protector highlights where the needle *was* by highlighting missing time, translating ambiguous forensic scenarios ("did they delete tracks?") into concrete start and end boundaries. 

## Workflow Fit
As a zero-dependency script native to standard Python environments, it fits perfectly on headless jumpboxes, live investigation environments, or as an embedded automated action in SIEM pipeline playbooks without necessitating `pip` packaging downloads or runtime deployments.

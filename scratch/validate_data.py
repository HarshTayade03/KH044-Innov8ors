"""
scratch/validate_data.py — Lightweight validation script for all data/ fixture files.

Parses every JSON fixture in data/ against the registered scanner parsers and
prints a per-file summary so contributors can quickly spot malformed records,
missing required fields, or fixtures that would cause ingestion failures.

Usage (run from the repository root):
    python scratch/validate_data.py

Requirements:
    No additional dependencies beyond requirements.txt.
    The virtual environment must be activated before running.

Exit codes:
    0 — all files parsed without errors
    1 — one or more files produced parse errors or zero valid records
"""

import json
import os
import sys
from pathlib import Path

# Add repository root to sys.path so src.app.parsers can be imported.
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Import parsers — this also registers them in the PARSER_REGISTRY.
from src.app.parsers import nessus, burp, snyk, trivy, sarif  # noqa: F401
from src.app.parsers.base import PARSER_REGISTRY, normalize_cve, normalize_cwe, normalize_severity

DATA_DIR = REPO_ROOT / "data"

# Map fixture filenames to (parser_name, is_sarif) tuples.
# Files not listed here are ignored (e.g. README.md, cisa_kev_mock.json).
FIXTURE_PARSERS: dict[str, tuple[str, bool]] = {
    "burp_sqli.sarif":        ("sarif",   True),
    "burp_xss.sarif":         ("sarif",   True),
    "nessus_ssrf.sarif":      ("sarif",   True),
    "nessus_sqli.json":       ("nessus",  False),
    "nessus_edge_cases.json": ("nessus",  False),
    "burp_ssrf.json":         ("burp",    False),
    "zap_xss.json":           ("zap",     False),
    "snyk_sca.json":          ("snyk",    False),
    "trivy_container.json":   ("trivy",   False),
    "rapid7_insightvm.json":  ("nessus",  False),  # Rapid7 uses the Nessus parser
}

ANSI_GREEN  = "\033[92m"
ANSI_YELLOW = "\033[93m"
ANSI_RED    = "\033[91m"
ANSI_RESET  = "\033[0m"
ANSI_BOLD   = "\033[1m"


def colour(text: str, code: str) -> str:
    """Wrap text in ANSI colour code if stdout is a TTY."""
    if sys.stdout.isatty():
        return f"{code}{text}{ANSI_RESET}"
    return text


def extract_records_from_sarif(data: dict) -> list[dict]:
    """Flatten all results from all SARIF runs into a list of records."""
    records = []
    for run in data.get("runs", []):
        records.extend(run.get("results", []))
    return records


def validate_file(filepath: Path, parser_name: str, is_sarif: bool) -> dict:
    """
    Parse a single fixture file and return a validation summary dict.

    Returns:
        {
            "file": str,
            "parser": str,
            "total": int,
            "valid": int,
            "warnings": int,     # records with _comment keys (edge cases)
            "parse_errors": int,
            "issues": list[str], # human-readable issue descriptions
        }
    """
    summary = {
        "file": filepath.name,
        "parser": parser_name,
        "total": 0,
        "valid": 0,
        "warnings": 0,
        "parse_errors": 0,
        "issues": [],
    }

    # ── Load JSON ─────────────────────────────────────────────────────────────
    try:
        with filepath.open(encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        summary["issues"].append(f"JSON decode error: {exc}")
        summary["parse_errors"] += 1
        return summary

    # ── Extract records ────────────────────────────────────────────────────────
    if is_sarif:
        if not isinstance(data, dict):
            summary["issues"].append("SARIF file must be a JSON object at the root level.")
            summary["parse_errors"] += 1
            return summary
        records = extract_records_from_sarif(data)
    else:
        if isinstance(data, dict):
            records = [data]
        elif isinstance(data, list):
            records = data
        else:
            summary["issues"].append("File must be a JSON object or array.")
            summary["parse_errors"] += 1
            return summary

    summary["total"] = len(records)

    if summary["total"] == 0:
        summary["issues"].append("File contains zero records.")
        return summary

    # ── Retrieve parser ────────────────────────────────────────────────────────
    parser = PARSER_REGISTRY.get(parser_name)
    if parser is None:
        summary["issues"].append(f"No parser registered for '{parser_name}'.")
        summary["parse_errors"] += 1
        return summary

    # ── Parse each record ──────────────────────────────────────────────────────
    for idx, record in enumerate(records):
        # Skip annotation-only records (fully empty or comment-only).
        if isinstance(record, dict) and all(k.startswith("_") for k in record):
            summary["warnings"] += 1
            continue

        # Records with a _comment are edge-case entries — still attempt to parse.
        has_comment = isinstance(record, dict) and "_comment" in record
        if has_comment:
            summary["warnings"] += 1

        try:
            parsed = parser.parse(record)
        except Exception as exc:
            summary["parse_errors"] += 1
            summary["issues"].append(f"Record [{idx}] raised {type(exc).__name__}: {exc}")
            continue

        # Check for parse error sentinel returned by parse_batch().
        if "__parse_error__" in parsed:
            summary["parse_errors"] += 1
            summary["issues"].append(f"Record [{idx}] parse error: {parsed['__parse_error__']}")
            continue

        # ── Field-level spot checks ────────────────────────────────────────────
        title = parsed.get("title")
        if not title:
            summary["issues"].append(f"Record [{idx}] has no title after parsing.")

        severity_raw = parsed.get("severity_raw")
        canonical, _ = normalize_severity(severity_raw)
        if canonical == "Unknown" and not has_comment:
            summary["issues"].append(
                f"Record [{idx}] severity '{severity_raw}' normalised to Unknown "
                f"(consider using Critical/High/Medium/Low/Informational)."
            )

        for cve in parsed.get("cve_ids", []):
            normalised = normalize_cve(cve)
            if normalised is None:
                summary["issues"].append(
                    f"Record [{idx}] CVE '{cve}' could not be normalised — will be dropped."
                )

        for cwe in parsed.get("cwe_ids", []):
            normalised = normalize_cwe(cwe)
            if normalised is None:
                summary["issues"].append(
                    f"Record [{idx}] CWE '{cwe}' could not be normalised — will be dropped."
                )

        cvss = parsed.get("cvss_score")
        if cvss is not None:
            try:
                score = float(cvss)
                if not (0.0 <= score <= 10.0):
                    summary["issues"].append(
                        f"Record [{idx}] CVSS score {score} is outside the valid 0–10 range."
                    )
            except (ValueError, TypeError):
                summary["issues"].append(
                    f"Record [{idx}] CVSS score '{cvss}' is not numeric."
                )

        summary["valid"] += 1

    return summary


def print_summary(summary: dict) -> bool:
    """Print a formatted summary block. Returns True if the file is clean."""
    total   = summary["total"]
    valid   = summary["valid"]
    errors  = summary["parse_errors"]
    warn    = summary["warnings"]
    issues  = summary["issues"]

    if errors > 0:
        status = colour("FAIL", ANSI_RED)
    elif issues:
        status = colour("WARN", ANSI_YELLOW)
    else:
        status = colour(" OK ", ANSI_GREEN)

    print(f"[{status}]  {summary['file']:<35}  parser={summary['parser']:<8}  "
          f"records={total}  valid={valid}  edge-cases={warn}  errors={errors}")

    for issue in issues:
        prefix = colour("      ↳", ANSI_YELLOW)
        print(f"{prefix} {issue}")

    return errors == 0 and valid > 0


def main() -> int:
    print(colour(f"\n{'─' * 70}", ANSI_BOLD))
    print(colour("  AI-Assisted Vulnerability Triage Platform — Data Fixture Validator", ANSI_BOLD))
    print(colour(f"  Scanning: {DATA_DIR}", ANSI_BOLD))
    print(colour(f"{'─' * 70}\n", ANSI_BOLD))

    all_ok = True
    checked = 0

    for filename, (parser_name, is_sarif) in sorted(FIXTURE_PARSERS.items()):
        filepath = DATA_DIR / filename
        if not filepath.exists():
            print(colour(f"[SKIP]  {filename:<35}  (file not found)", ANSI_YELLOW))
            continue

        summary = validate_file(filepath, parser_name, is_sarif)
        ok = print_summary(summary)
        if not ok:
            all_ok = False
        checked += 1

    print(f"\n{'─' * 70}")
    print(f"  Checked {checked} fixture file(s).")

    if all_ok:
        print(colour("  Result: all fixtures valid.\n", ANSI_GREEN))
        return 0
    else:
        print(colour("  Result: one or more fixtures have errors — see above.\n", ANSI_RED))
        return 1


if __name__ == "__main__":
    sys.exit(main())

"""
logger.py — Structured Attempt Logger
======================================
CEH Topic: Footprinting & Reconnaissance (logging is the defender's equivalent)

Writes login attempt data to:
  - JSON log file (machine-readable, for SIEM integration)
  - Human-readable summary report (TXT)

Educational Note:
  IDS/IPS systems and SIEMs (like Splunk, ELK) ingest logs exactly like
  these to detect brute-force patterns in real time.
"""

import json
import os
from datetime import datetime
from pathlib import Path


LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)


class AttemptLogger:
    def __init__(self, session_id: str = ""):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_id  = session_id or ts
        self.json_path   = LOG_DIR / f"session_{self.session_id}.json"
        self.report_path = LOG_DIR / f"report_{self.session_id}.txt"
        self._entries: list[dict] = []

    def log(self, entry: dict):
        entry["_ts"] = datetime.now().isoformat()
        self._entries.append(entry)
        with open(self.json_path, "w") as f:
            json.dump(self._entries, f, indent=2)

    def write_summary(self, result):
        """Write a human-readable attack summary report."""
        lines = [
            "=" * 60,
            "  BRUTE FORCE SIMULATION — SUMMARY REPORT",
            f"  Session : {self.session_id}",
            f"  Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 60,
            f"  Total Attempts  : {result.total_attempts}",
            f"  Successful Logins: {result.success_count}",
            f"  Blocked Attempts : {result.blocked_count}",
            f"  Password Found  : {result.found_password or 'NOT FOUND'}",
            f"  Time Elapsed    : {result.total_time:.2f}s",
            f"  Stopped Early   : {result.was_stopped}",
            "=" * 60,
            "",
            "  ATTEMPT LOG (last 20):",
        ]
        for a in result.attempts[-20:]:
            status = "✓" if a["success"] else ("⊘" if a["blocked"] else "✗")
            lines.append(
                f"  [{status}] {a['username']} / {a['password']:<20} | {a['reason']}"
            )
        lines += ["", "  Defensive mechanisms activated during this session:"]
        if any(a["delay"] > 0 for a in result.attempts):
            lines.append("  ✔ Progressive delay (exponential backoff)")
        if any(a["locked"] for a in result.attempts):
            lines.append("  ✔ Account lockout triggered")
        if any(a["captcha"] for a in result.attempts):
            lines.append("  ✔ CAPTCHA challenge issued")
        lines.append("=" * 60)

        with open(self.report_path, "w") as f:
            f.write("\n".join(lines))
        return self.report_path

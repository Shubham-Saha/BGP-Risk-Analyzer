"""Crawl timing -- collect per-pod metrics and write crawl time summary CSV."""

import csv
import threading
import time
from datetime import datetime, timezone

from config import CRAWL_TIME_CSV_HEADERS, CRAWL_TIME_SUMMARY_FILE, RESULTS_DIR

# Old filename used before the rename (for migration)
_OLD_BENCHMARK_FILE = RESULTS_DIR / "crawl_benchmarks.csv"


class CrawlTimer:
    """Collects per-pod timing records and computes crawl-level benchmarks.

    Thread-safe: record_pod() can be called from any thread.
    """

    def __init__(self, total_offerings: int, platform: str = "PI", parallelism: int = 1):
        self._lock = threading.Lock()
        self.total_offerings = total_offerings
        self.platform = platform
        self.parallelism = parallelism
        self.pod_records: list[dict] = []
        self.crawl_start: float | None = None
        self.crawl_end: float | None = None

    def start_crawl(self):
        """Record the crawl start time."""
        self.crawl_start = time.time()

    def end_crawl(self):
        """Record the crawl end time."""
        self.crawl_end = time.time()

    def record_pod(self, timings: dict):
        """Add a pod's timing record (thread-safe).

        Expected keys in timings dict:
            spinup_seconds: float | None
            termination_seconds: float | None
            ipinfo_seconds: float | None
            prefix_seconds: float | None
            rpki_seconds: float | None
            pod_end_to_end_seconds: float | None
            had_error: bool
            error_type: str | None  (timeout, terminal_status, active_no_ip, etc.)
        """
        with self._lock:
            self.pod_records.append(timings)

    def compute_summary(self) -> dict:
        """Compute all benchmark metrics from collected records."""
        records = self.pod_records
        n = len(records)

        def _avg(key):
            vals = [r[key] for r in records if r.get(key) is not None]
            return round(sum(vals) / len(vals), 2) if vals else None

        avg_spinup = _avg("spinup_seconds")
        avg_term = _avg("termination_seconds")

        # Combined provisioning + termination
        combined_vals = [
            r["spinup_seconds"] + r["termination_seconds"]
            for r in records
            if r.get("spinup_seconds") is not None
            and r.get("termination_seconds") is not None
        ]
        avg_prov_term = (
            round(sum(combined_vals) / len(combined_vals), 2)
            if combined_vals
            else None
        )

        avg_ipinfo = _avg("ipinfo_seconds")

        # Combined prefix lookup + RPKI validation (both query RIPE Stat)
        ripe_combined = [
            r["prefix_seconds"] + r["rpki_seconds"]
            for r in records
            if r.get("prefix_seconds") is not None
            and r.get("rpki_seconds") is not None
        ]
        avg_ripe = (
            round(sum(ripe_combined) / len(ripe_combined), 2)
            if ripe_combined
            else None
        )

        avg_e2e = _avg("pod_end_to_end_seconds")

        failed_count = sum(1 for r in records if r.get("had_error"))

        # Failure breakdown by error type
        fail_timeout = sum(1 for r in records if r.get("error_type") == "timeout")
        fail_terminal = sum(1 for r in records if r.get("error_type") == "terminal_status")
        fail_no_ip = sum(1 for r in records if r.get("error_type") == "active_no_ip")
        fail_other = failed_count - fail_timeout - fail_terminal - fail_no_ip

        total_crawl = (
            round(self.crawl_end - self.crawl_start, 2)
            if self.crawl_start and self.crawl_end
            else None
        )

        def _fmt(val):
            return str(val) if val is not None else ""

        return {
            "Crawl Timestamp": datetime.now(timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            ),
            "Platform": self.platform,
            "Parallel": self.parallelism,
            "Total Offerings": self.total_offerings,
            "Pods Processed": n,
            "Pods Failed/Timed Out": failed_count,
            "Failures: Timeout (8min)": fail_timeout,
            "Failures: Terminal Status": fail_terminal,
            "Failures: Active No IP": fail_no_ip,
            "Failures: API/Other": fail_other,
            "Avg Provisioning + IP Time (s)": _fmt(avg_spinup),
            "Avg Termination Time (s)": _fmt(avg_term),
            "Avg Provisioning + IP + Termination (s)": _fmt(avg_prov_term),
            "Avg RIPE Stat IP Lookup Time (s)": _fmt(avg_ipinfo),
            "Avg Prefix Lookup + RPKI Validation Time (s)": _fmt(avg_ripe),
            "Avg End-to-End Per Pod (s)": _fmt(avg_e2e),
            "Total Crawl Time (s)": _fmt(total_crawl),
        }

    @staticmethod
    def _migrate_crawl_time_file():
        """Rename old crawl_benchmarks.csv -> crawl_time_summary.csv and add Platform column."""
        # Step 1: Rename old file if it exists and new file does not
        if _OLD_BENCHMARK_FILE.exists() and not CRAWL_TIME_SUMMARY_FILE.exists():
            _OLD_BENCHMARK_FILE.rename(CRAWL_TIME_SUMMARY_FILE)
            print(f"  Renamed {_OLD_BENCHMARK_FILE.name} -> {CRAWL_TIME_SUMMARY_FILE.name}")

        if not CRAWL_TIME_SUMMARY_FILE.exists():
            return

        # Step 2: Check if headers need migration (add Platform column)
        try:
            with open(CRAWL_TIME_SUMMARY_FILE, "r", newline="", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f, delimiter=";")
                existing = reader.fieldnames or []
                if set(existing) == set(CRAWL_TIME_CSV_HEADERS):
                    return  # already current
                rows = list(reader)
        except Exception:
            return

        # Rewrite with current headers, backfill Platform with "PI" for old rows
        # Rename map for columns that changed names
        _RENAME = {"Avg ipinfo.io Time (s)": "Avg RIPE Stat IP Lookup Time (s)"}
        with open(CRAWL_TIME_SUMMARY_FILE, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=CRAWL_TIME_CSV_HEADERS, delimiter=";")
            writer.writeheader()
            for row in rows:
                for old_key, new_key in _RENAME.items():
                    if old_key in row and new_key not in row:
                        row[new_key] = row.pop(old_key)
                for h in CRAWL_TIME_CSV_HEADERS:
                    row.setdefault(h, "")
                if not row.get("Platform"):
                    row["Platform"] = "PI"
                writer.writerow(row)

        print(f"  Migrated crawl time summary to {len(CRAWL_TIME_CSV_HEADERS)}-column format.")

    def save_crawl_time_csv(self) -> dict:
        """Compute summary and append one row to the crawl time summary CSV."""
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        self._migrate_crawl_time_file()
        summary = self.compute_summary()

        file_exists = CRAWL_TIME_SUMMARY_FILE.exists()
        mode = "a" if file_exists else "w"
        encoding = "utf-8" if file_exists else "utf-8-sig"

        with open(CRAWL_TIME_SUMMARY_FILE, mode, newline="", encoding=encoding) as f:
            writer = csv.DictWriter(
                f, fieldnames=CRAWL_TIME_CSV_HEADERS, delimiter=";"
            )
            if not file_exists:
                writer.writeheader()
            writer.writerow(summary)

        print(f"\n  Crawl time results saved to: {CRAWL_TIME_SUMMARY_FILE}")
        self._print_summary(summary)
        return summary

    def _print_summary(self, summary: dict):
        """Print a readable summary to the console."""
        failed = summary['Pods Failed/Timed Out']
        print(f"\n  -- Crawl Time Summary ({summary['Platform']}) --")
        print(f"    Parallel:                 {summary['Parallel']}")
        print(f"    Pods processed:           {summary['Pods Processed']}/{summary['Total Offerings']}")
        print(f"    Pods failed/timed out:    {failed}")
        if failed:
            print(f"      Timeout (8min):         {summary['Failures: Timeout (8min)']}")
            print(f"      Terminal status:         {summary['Failures: Terminal Status']}")
            print(f"      Active but no IP:       {summary['Failures: Active No IP']}")
            print(f"      API/other:              {summary['Failures: API/Other']}")
        print(f"    Avg provisioning + IP:    {summary['Avg Provisioning + IP Time (s)']}s")
        print(f"    Avg termination:          {summary['Avg Termination Time (s)']}s")
        print(f"    Avg RIPE Stat IP lookup:  {summary['Avg RIPE Stat IP Lookup Time (s)']}s")
        print(f"    Avg RIPE Stat (prefix+RPKI): {summary['Avg Prefix Lookup + RPKI Validation Time (s)']}s")
        print(f"    Avg end-to-end per pod:   {summary['Avg End-to-End Per Pod (s)']}s")
        print(f"    Total crawl time:         {summary['Total Crawl Time (s)']}s")

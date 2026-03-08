"""Analysis module -- real-time analysis of collected scan and ping data."""

import csv
from collections import defaultdict

from config import (
    CRAWL_TIME_SUMMARY_FILE,
    IP_PING_STATUS_FILE,
    PRIME_CHANGES_CSV_FILE,
    PRIME_CSV_FILE,
    UNIQUE_IPS_CSV_FILE,
    VAST_CHANGES_CSV_FILE,
    VAST_CSV_FILE,
)


ANALYSIS_MENU = """
  ╔══════════════════════════════════════════════╗
  ║              Analysis Menu                   ║
  ╚══════════════════════════════════════════════╝

  [1] Crawl Overview
  [2] Ping Status Change Analysis
  [3] Crawl Change Frequency Analysis
  [4] EROSION Risk Distribution
  [5] ROA Coverage Analysis
  [6] ASN Concentration Analysis
  [0] Back to main menu
"""


def run_analysis_menu():
    """Display analysis sub-menu and handle selection."""
    while True:
        print(ANALYSIS_MENU)
        choice = input("  Select analysis: ").strip()

        if choice == "0":
            break
        elif choice == "1":
            _crawl_overview_standalone()
        elif choice == "2":
            _ping_status_change_analysis()
        elif choice == "3":
            _crawl_change_frequency_analysis()
        elif choice == "4":
            _erosion_risk_distribution()
        elif choice == "5":
            _roa_coverage_analysis()
        elif choice == "6":
            _asn_concentration_analysis()
        else:
            print("  Invalid option. Please select 0-6.")


# ---------------------------------------------------------------------------
#  [1] Crawl Overview
# ---------------------------------------------------------------------------

def _crawl_overview_standalone():
    """Display crawl overview as a standalone analysis option."""
    unique_rows = _load_unique_ips()
    if unique_rows is None:
        return

    print()
    print("  " + "=" * 60)
    print("   Crawl Overview")
    print("  " + "=" * 60)
    _print_crawl_overview(unique_rows)
    print()
    print("  " + "=" * 60)


# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

def _pct(n: int, d: int) -> str:
    return f"{n / d * 100:.1f}%" if d > 0 else "N/A"


def _ask_top_n(label: str, default: int = 10) -> int | None:
    """Ask user how many to show. Returns None for 'all'."""
    raw = input(f"\n  Show top N {label} [default={default}, 'all' for all]: ").strip()
    if raw.lower() == "all":
        return None
    if raw.isdigit() and int(raw) > 0:
        return int(raw)
    return default


def _load_unique_ips() -> list[dict] | None:
    """Load unique_scan_ips.csv, return rows or None."""
    if not UNIQUE_IPS_CSV_FILE.exists():
        print("\n  No unique_scan_ips.csv found. Run a scan and refresh unique IPs first.")
        return None
    with open(UNIQUE_IPS_CSV_FILE, "r", newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f, delimiter=";"))


def _load_crawl_summary() -> list[dict]:
    """Load crawl_time_summary.csv rows."""
    if not CRAWL_TIME_SUMMARY_FILE.exists():
        return []
    try:
        with open(CRAWL_TIME_SUMMARY_FILE, "r", newline="", encoding="utf-8-sig") as f:
            return list(csv.DictReader(f, delimiter=";"))
    except Exception:
        return []


def _safe_float(val: str) -> float:
    """Parse a string to float, returning 0.0 on failure."""
    try:
        return float(val)
    except (ValueError, TypeError):
        return 0.0


def _safe_int(val: str) -> int:
    """Parse a string to int, returning 0 on failure."""
    try:
        return int(val)
    except (ValueError, TypeError):
        return 0


def _print_crawl_overview(unique_rows: list[dict]):
    """Print crawl overview with per-platform stats from crawl_time_summary.csv."""
    crawl_rows = _load_crawl_summary()
    if not crawl_rows:
        return

    # Split by platform
    pi_crawls = [r for r in crawl_rows if r.get("Platform", "").strip() == "PI"]
    vast_crawls = [r for r in crawl_rows if r.get("Platform", "").strip() == "Vast"]

    # Count unique IPs per platform from unique_rows
    pi_ips = set()
    vast_ips = set()
    for r in unique_rows:
        ip = r.get("IP Addresses", "").strip()
        plat = r.get("Platform", "").strip()
        if ip:
            if plat == "PI":
                pi_ips.add(ip)
            elif plat == "Vast":
                vast_ips.add(ip)

    # Date ranges
    def _date_range(rows: list[dict]) -> tuple[str, str]:
        timestamps = [r.get("Crawl Timestamp", "").strip()[:10] for r in rows
                      if r.get("Crawl Timestamp", "").strip()]
        if not timestamps:
            return ("", "")
        return (min(timestamps), max(timestamps))

    pi_start, pi_end = _date_range(pi_crawls)
    vast_start, vast_end = _date_range(vast_crawls)
    all_start = min(filter(None, [pi_start, vast_start]), default="")
    all_end = max(filter(None, [pi_end, vast_end]), default="")

    print()
    print("   Crawl Overview")
    print("  " + "-" * 60)
    print(f"   {'Platform':<14}{'Crawls':>7}   {'Period':<28}{'Unique IPs':>10}")
    if pi_crawls:
        print(f"   {'PI':<14}{len(pi_crawls):>7}   {pi_start} -> {pi_end:<16}{len(pi_ips):>10,}")
    if vast_crawls:
        print(f"   {'Vast.ai':<14}{len(vast_crawls):>7}   {vast_start} -> {vast_end:<16}{len(vast_ips):>10,}")
    total_crawls = len(pi_crawls) + len(vast_crawls)
    total_ips = len(pi_ips | vast_ips)
    print(f"   {'Total':<14}{total_crawls:>7}   {all_start} -> {all_end:<16}{total_ips:>10,}")

    # -- Performance Summary ---------------------------------------------------
    def _avg(rows: list[dict], col: str) -> float:
        vals = [_safe_float(r.get(col, "")) for r in rows if r.get(col, "").strip()]
        return sum(vals) / len(vals) if vals else 0.0

    def _total(rows: list[dict], col: str) -> int:
        return sum(_safe_int(r.get(col, "")) for r in rows)

    has_pi = bool(pi_crawls)
    has_vast = bool(vast_crawls)

    print()
    print("   Performance Summary (averaged across crawls)")
    print("  " + "-" * 60)
    hdr = "   {:<38}"
    if has_pi:
        hdr += "{:>12}"
    if has_vast:
        hdr += "{:>12}"
    cols = [""]
    if has_pi:
        cols.append("PI")
    if has_vast:
        cols.append("Vast.ai")
    print(hdr.format(*cols))

    def _row(label: str, pi_val: str, vast_val: str):
        fmt = f"   {label:<38}"
        if has_pi:
            fmt += f"{pi_val:>12}"
        if has_vast:
            fmt += f"{vast_val:>12}"
        print(fmt)

    # IPs scanned per crawl
    pi_avg_ips = round(_avg(pi_crawls, "Pods Processed")) if has_pi else 0
    vast_avg_ips = round(_avg(vast_crawls, "Pods Processed")) if has_vast else 0
    _row("IPs Scanned per Crawl:",
         str(pi_avg_ips) if has_pi else "-",
         str(vast_avg_ips) if has_vast else "-")

    # Crawl duration
    pi_avg_dur = _avg(pi_crawls, "Total Crawl Time (s)")
    vast_avg_dur = _avg(vast_crawls, "Total Crawl Time (s)")
    _row("Crawl Duration:",
         f"{pi_avg_dur:,.1f}s" if has_pi else "-",
         f"{vast_avg_dur:,.1f}s" if has_vast else "-")

    # End-to-end per IP
    pi_avg_e2e = _avg(pi_crawls, "Avg End-to-End Per Pod (s)")
    vast_avg_e2e = _avg(vast_crawls, "Avg End-to-End Per Pod (s)")
    _row("End-to-End per IP:",
         f"{pi_avg_e2e:.1f}s" if has_pi else "-",
         f"{vast_avg_e2e:.1f}s" if has_vast else "-")

    # API lookup per IP (RIPE Stat)
    pi_avg_api = _avg(pi_crawls, "Avg RIPE Stat IP Lookup Time (s)")
    vast_avg_api = _avg(vast_crawls, "Avg RIPE Stat IP Lookup Time (s)")
    _row("API Lookup per IP (RIPE Stat):",
         f"{pi_avg_api:.1f}s" if has_pi else "-",
         f"{vast_avg_api:.1f}s" if has_vast else "-")

    # RPKI validation per IP
    pi_avg_rpki = _avg(pi_crawls, "Avg Prefix Lookup + RPKI Validation Time (s)")
    vast_avg_rpki = _avg(vast_crawls, "Avg Prefix Lookup + RPKI Validation Time (s)")
    _row("RPKI Validation per IP:",
         f"{pi_avg_rpki:.1f}s" if has_pi else "-",
         f"{vast_avg_rpki:.1f}s" if has_vast else "-")

    # Pod provisioning (PI only)
    if has_pi:
        pi_avg_prov = _avg(pi_crawls, "Avg Provisioning + IP Time (s)")
        _row("Pod Provisioning per IP (PI only):",
             f"{pi_avg_prov:.1f}s", "-" if has_vast else "")

    # -- Failure Summary -------------------------------------------------------
    print()
    print("   Failure Summary (totals across all crawls)")
    print("  " + "-" * 60)

    pi_total_scanned = _total(pi_crawls, "Pods Processed")
    pi_total_failed = _total(pi_crawls, "Pods Failed/Timed Out")
    vast_total_scanned = _total(vast_crawls, "Pods Processed")
    vast_total_failed = _total(vast_crawls, "Pods Failed/Timed Out")

    _row("Total IPs Scanned:",
         f"{pi_total_scanned:,}" if has_pi else "-",
         f"{vast_total_scanned:,}" if has_vast else "-")
    _row("Total Failures:",
         f"{pi_total_failed:,}" if has_pi else "-",
         f"{vast_total_failed:,}" if has_vast else "-")
    _row("Failure Rate:",
         _pct(pi_total_failed, pi_total_scanned) if has_pi else "-",
         _pct(vast_total_failed, vast_total_scanned) if has_vast else "-")

    # PI failure breakdown
    if has_pi and pi_total_failed > 0:
        pi_timeout = _total(pi_crawls, "Failures: Timeout (8min)")
        pi_terminal = _total(pi_crawls, "Failures: Terminal Status")
        pi_no_ip = _total(pi_crawls, "Failures: Active No IP")
        pi_api = _total(pi_crawls, "Failures: API/Other")

        print()
        print(f"   PI Failure Breakdown ({pi_total_failed:,} total):")
        print(f"     Timeout (8min):             {pi_timeout:>6,}  ({_pct(pi_timeout, pi_total_failed)})")
        print(f"     Terminal Status:             {pi_terminal:>6,}  ({_pct(pi_terminal, pi_total_failed)})")
        print(f"     Active No IP:               {pi_no_ip:>6,}  ({_pct(pi_no_ip, pi_total_failed)})")
        print(f"     API/Other:                  {pi_api:>6,}  ({_pct(pi_api, pi_total_failed)})")

    # Vast failure breakdown
    if has_vast and vast_total_failed > 0:
        vast_timeout = _total(vast_crawls, "Failures: Timeout (8min)")
        vast_terminal = _total(vast_crawls, "Failures: Terminal Status")
        vast_no_ip = _total(vast_crawls, "Failures: Active No IP")
        vast_api = _total(vast_crawls, "Failures: API/Other")

        print()
        print(f"   Vast.ai Failure Breakdown ({vast_total_failed:,} total):")
        if vast_timeout:
            print(f"     Timeout:                    {vast_timeout:>6,}  ({_pct(vast_timeout, vast_total_failed)})")
        if vast_terminal:
            print(f"     Terminal Status:             {vast_terminal:>6,}  ({_pct(vast_terminal, vast_total_failed)})")
        if vast_no_ip:
            print(f"     Active No IP:               {vast_no_ip:>6,}  ({_pct(vast_no_ip, vast_total_failed)})")
        if vast_api:
            print(f"     API/Other:                  {vast_api:>6,}  ({_pct(vast_api, vast_total_failed)})")


def _load_crawl_counts() -> dict[str, int]:
    """Load max crawl number per IP from both platform result CSVs."""
    counts: dict[str, int] = {}

    for csv_path, ip_col in [(VAST_CSV_FILE, "IP Address"), (PRIME_CSV_FILE, "Pod ID")]:
        if not csv_path.exists():
            continue
        try:
            with open(csv_path, "r", newline="", encoding="utf-8-sig") as f:
                for row in csv.DictReader(f, delimiter=";"):
                    ip = row.get(ip_col, "").strip()
                    crawl = row.get("Crawl Number", "").strip()
                    if ip and crawl.isdigit():
                        counts[ip] = max(counts.get(ip, 0), int(crawl))
        except Exception:
            pass

    return counts


def _load_changes() -> tuple[list[dict], list[dict]]:
    """Load change CSVs for both platforms. Returns (vast_changes, pi_changes)."""
    vast_changes: list[dict] = []
    pi_changes: list[dict] = []

    if VAST_CHANGES_CSV_FILE.exists():
        with open(VAST_CHANGES_CSV_FILE, "r", newline="", encoding="utf-8-sig") as f:
            vast_changes = list(csv.DictReader(f, delimiter=";"))

    if PRIME_CHANGES_CSV_FILE.exists():
        with open(PRIME_CHANGES_CSV_FILE, "r", newline="", encoding="utf-8-sig") as f:
            pi_changes = list(csv.DictReader(f, delimiter=";"))

    return vast_changes, pi_changes


# ---------------------------------------------------------------------------
#  [1] Ping Status Change Analysis
# ---------------------------------------------------------------------------

def _ping_status_change_analysis():
    """Compare original scan ping status with latest ping test results."""

    unique_rows = _load_unique_ips()
    if unique_rows is None:
        return

    # Build lookup: IP -> {original status, platform}
    original: dict[str, dict] = {}
    for r in unique_rows:
        ip = r.get("IP Addresses", "").strip()
        if ip:
            original[ip] = {
                "status": r.get("Ping Status", "").strip(),
                "platform": r.get("Platform", "").strip(),
            }

    # Load ping status CSV
    if not IP_PING_STATUS_FILE.exists():
        print("\n  No ip_ping_status.csv found. Run a Ping Test [7] first.")
        return

    with open(IP_PING_STATUS_FILE, "r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f, delimiter=";")
        ping_headers = list(reader.fieldnames or [])
        ping_rows = list(reader)

    status_cols = [h for h in ping_headers if h.startswith("Status on ")]
    if not status_cols:
        print("\n  No ping status snapshots found in ip_ping_status.csv.")
        return

    latest_col = status_cols[-1]

    ping_data: dict[str, str] = {}
    for r in ping_rows:
        ip = r.get("IP Address", "").strip()
        if ip:
            ping_data[ip] = r.get(latest_col, "").strip()

    # Compute comparison
    matched_ips = set(original.keys()) & set(ping_data.keys())

    unchanged = 0
    active_to_inactive = 0
    inactive_to_active = 0
    platform_stats: dict[str, dict] = {}

    for ip in matched_ips:
        orig_status = original[ip]["status"]
        plat = original[ip]["platform"]
        new_status = ping_data[ip]

        orig_alive = orig_status.lower() == "active"
        new_alive = new_status.lower() == "active"

        if plat not in platform_stats:
            platform_stats[plat] = {"total": 0, "unchanged": 0, "a2i": 0, "i2a": 0}
        platform_stats[plat]["total"] += 1

        if orig_alive == new_alive:
            unchanged += 1
            platform_stats[plat]["unchanged"] += 1
        elif orig_alive and not new_alive:
            active_to_inactive += 1
            platform_stats[plat]["a2i"] += 1
        else:
            inactive_to_active += 1
            platform_stats[plat]["i2a"] += 1

    total = len(matched_ips)
    total_changed = active_to_inactive + inactive_to_active

    orig_active = sum(1 for v in original.values() if v["status"].lower() == "active")
    orig_inactive = len(original) - orig_active
    new_active = sum(1 for v in ping_data.values() if v.lower() == "active")
    new_inactive = len(ping_data) - new_active

    # Display
    print()
    print("  " + "=" * 60)
    print("   Ping Status Change Analysis")
    print(f"   Comparing: Original Scan Data  vs  {latest_col}")
    print("  " + "=" * 60)

    print()
    print("   Overall Summary")
    print("  " + "-" * 46)
    print(f"   Total IPs analyzed:     {total:,}")
    print()
    print(f"                        {'During Scan':>12}  {'Now':>8}")
    print(f"   Active:              {orig_active:>12,}  {new_active:>8,}")
    print(f"   Inactive:            {orig_inactive:>12,}  {new_inactive:>8,}")

    print()
    print("   Status Changes")
    print("  " + "-" * 46)
    print(f"   Unchanged:              {unchanged:>5,}  ({_pct(unchanged, total)})")
    print(f"   Active -> Inactive:     {active_to_inactive:>5,}  ({_pct(active_to_inactive, total)})")
    print(f"   Inactive -> Active:     {inactive_to_active:>5,}  ({_pct(inactive_to_active, total)})")
    print(f"   Total changed:          {total_changed:>5,}  ({_pct(total_changed, total)})")

    print()
    print("   By Platform")
    print("  " + "-" * 46)
    for plat in sorted(platform_stats.keys()):
        ps = platform_stats[plat]
        pt = ps["total"]
        p_changed = ps["a2i"] + ps["i2a"]
        turnover = _pct(p_changed, pt)
        print(f"   {plat} ({pt:,} IPs):")
        print(f"     Unchanged:            {ps['unchanged']:>5,}  ({_pct(ps['unchanged'], pt)})")
        print(f"     Active -> Inactive:   {ps['a2i']:>5,}")
        print(f"     Inactive -> Active:   {ps['i2a']:>5,}")
        print(f"     IP Turnover Rate:     {turnover}")
        print()

    print("  " + "=" * 60)


# ---------------------------------------------------------------------------
#  [2] Crawl Change Frequency Analysis
# ---------------------------------------------------------------------------

def _crawl_change_frequency_analysis():
    """Analyze field change frequency across crawls for both platforms."""

    unique_rows = _load_unique_ips()
    if unique_rows is None:
        return

    vast_changes, pi_changes = _load_changes()
    all_changes = vast_changes + pi_changes

    if not all_changes:
        print("\n  No change data found. Need at least 2 crawls per platform.")
        return

    # Build IP -> ASN/Company/Erosion lookup from unique IPs
    ip_to_asn: dict[str, str] = {}
    ip_to_company: dict[str, str] = {}
    ip_to_erosion: dict[str, str] = {}
    for r in unique_rows:
        ip = r.get("IP Addresses", "").strip()
        if ip:
            ip_to_asn[ip] = r.get("ASN", "").strip()
            ip_to_company[ip] = r.get("Company Name", "").strip()
            ip_to_erosion[ip] = r.get("Erosion Case?", "").strip()

    # IP key differs between platforms
    def _get_ip(row: dict) -> str:
        return (row.get("IP Address", "") or row.get("Pod ID", "")).strip()

    # -- Change Coverage -----------------------------------------------------
    all_ips_with_changes = set()
    for r in all_changes:
        ip = _get_ip(r)
        if ip:
            all_ips_with_changes.add(ip)

    total_unique = len(set(
        r.get("IP Addresses", "").strip() for r in unique_rows
        if r.get("IP Addresses", "").strip()
    ))

    # Per-platform counts
    vast_changed_ips = set(_get_ip(r) for r in vast_changes if _get_ip(r))
    pi_changed_ips = set(_get_ip(r) for r in pi_changes if _get_ip(r))

    print()
    print("  " + "=" * 60)
    print("   Crawl Change Frequency Analysis")
    print(f"   {len(all_changes):,} change records across both platforms")
    print("  " + "=" * 60)

    print()
    print("   Change Coverage")
    print("  " + "-" * 46)
    print(f"   Total unique IPs/Pods:        {total_unique:,}")
    print(f"   IPs with changes:             {len(all_ips_with_changes):,}  ({_pct(len(all_ips_with_changes), total_unique)})")
    print(f"   IPs with zero changes:        {total_unique - len(all_ips_with_changes):,}  ({_pct(total_unique - len(all_ips_with_changes), total_unique)})")
    if vast_changes:
        print(f"     Vast.ai:  {len(vast_changed_ips):,} IPs with changes  ({len(vast_changes):,} records)")
    if pi_changes:
        print(f"     PI:       {len(pi_changed_ips):,} IPs with changes  ({len(pi_changes):,} records)")
    elif not PRIME_CHANGES_CSV_FILE.exists():
        print("     PI:       No change data yet (need 2+ crawls)")

    # -- Most Frequently Changed Fields --------------------------------------
    # Only count real changes (both previous and new values non-empty)
    field_counts: dict[str, int] = defaultdict(int)
    for r in all_changes:
        field = r.get("Field Changed", "").strip()
        prev = r.get("Previous Value", "").strip()
        new = r.get("New Value", "").strip()
        if field and prev and new:
            field_counts[field] += 1

    print()
    print("   Most Frequently Changed Fields")
    print("  " + "-" * 46)
    print(f"   {'Rank':<6}{'Field':<28}{'Changes':>8}")
    for rank, (field, count) in enumerate(
        sorted(field_counts.items(), key=lambda x: -x[1]), 1
    ):
        print(f"   {rank:<6}{field:<28}{count:>8,}")

    # -- Most Volatile IPs ---------------------------------------------------
    changes_per_ip: dict[str, int] = defaultdict(int)
    for r in all_changes:
        ip = _get_ip(r)
        prev = r.get("Previous Value", "").strip()
        new = r.get("New Value", "").strip()
        if ip and prev and new:
            changes_per_ip[ip] += 1

    crawl_counts = _load_crawl_counts()
    ranked_ips = sorted(changes_per_ip.items(), key=lambda x: -x[1])

    top_n = _ask_top_n("volatile IPs")
    display_ips = ranked_ips if top_n is None else ranked_ips[:top_n]

    print()
    print(f"   Most Volatile IPs (showing {len(display_ips):,})")
    print("  " + "-" * 46)
    print(f"   {'Rank':<6}{'IP':<22}{'Field Changes':>14}  {'Crawls':>6}  {'ASN':<12}{'Organization'}")
    for rank, (ip, count) in enumerate(display_ips, 1):
        asn = ip_to_asn.get(ip, "")
        company = ip_to_company.get(ip, "")
        crawls = crawl_counts.get(ip, "")
        if len(company) > 30:
            company = company[:27] + "..."
        print(f"   {rank:<6}{ip:<22}{count:>14,}  {crawls:>6}  {asn:<12}{company}")

    # -- ASNs by Change Frequency --------------------------------------------
    asn_total_changes: dict[str, int] = defaultdict(int)
    asn_changed_ips: dict[str, set] = defaultdict(set)
    for r in all_changes:
        ip = _get_ip(r)
        prev = r.get("Previous Value", "").strip()
        new = r.get("New Value", "").strip()
        if ip and prev and new:
            asn = ip_to_asn.get(ip, "Unknown")
            if asn:
                asn_total_changes[asn] += 1
                asn_changed_ips[asn].add(ip)

    ranked_asns = sorted(asn_total_changes.items(), key=lambda x: -x[1])

    top_n_asn = _ask_top_n("ASNs by change frequency")
    display_asns = ranked_asns if top_n_asn is None else ranked_asns[:top_n_asn]

    # Lookup ASN -> company name, total IPs per ASN, unique prefixes per ASN
    asn_to_company: dict[str, str] = {}
    asn_all_ips: dict[str, set] = defaultdict(set)
    asn_prefixes: dict[str, set] = defaultdict(set)
    for r in unique_rows:
        asn = r.get("ASN", "").strip()
        company = r.get("Company Name", "").strip()
        ip = r.get("IP Addresses", "").strip()
        prefix = r.get("Range", "").strip()
        if asn:
            if company and asn not in asn_to_company:
                asn_to_company[asn] = company
            if ip:
                asn_all_ips[asn].add(ip)
            if prefix:
                asn_prefixes[asn].add(prefix)

    # Build ASN -> erosion case breakdown
    asn_erosion: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for r in unique_rows:
        asn = r.get("ASN", "").strip()
        case = r.get("Erosion Case?", "").strip()
        if asn and case:
            asn_erosion[asn][case] += 1

    print()
    print(f"   ASNs by Change Frequency (showing {len(display_asns):,})")
    print("  " + "-" * 46)
    print(f"   {'Rank':<6}{'ASN':<12}{'Organization':<24}{'Total Field':>11}  {'IPs':>7}  {'IPs':>7}  {'BGP':>7}  {'EROSION Case'}")
    print(f"   {'':<6}{'':<12}{'':<24}{'Changes':>11}  {'Changed':>7}  {'Unchanged':>7}  {'Prefixes':>7}  {'Breakdown'}")
    print("  " + "-" * 100)
    for rank, (asn, count) in enumerate(display_asns, 1):
        company = asn_to_company.get(asn, "")
        if len(company) > 22:
            company = company[:19] + "..."
        n_changed = len(asn_changed_ips[asn])
        n_total = len(asn_all_ips.get(asn, set()))
        n_stable = n_total - n_changed
        n_prefixes = len(asn_prefixes.get(asn, set()))
        cases = asn_erosion.get(asn, {})
        case_str = "  ".join(f"Case {c}: {n} IPs" for c, n in sorted(cases.items()))
        print(f"   {rank:<6}{asn:<12}{company:<24}{count:>11,}  {n_changed:>7}  {n_stable:>7}  {n_prefixes:>7}  {case_str}")

    print()
    print("  " + "=" * 60)


# ---------------------------------------------------------------------------
#  [4] EROSION Risk Distribution
# ---------------------------------------------------------------------------

EROSION_DESCRIPTIONS = {
    "1": "ROA exists, MaxLength = prefix length",
    "2": "ROA exists, MaxLength > prefix length",
    "3": "No ROA, prefix is /24",
    "4": "No ROA, prefix larger than /24",
}


def _erosion_risk_distribution():
    """Show EROSION case distribution across all scanned IPs and ASNs."""
    unique_rows = _load_unique_ips()
    if unique_rows is None:
        return

    case_counts: dict[str, int] = defaultdict(int)
    asn_to_company: dict[str, str] = {}
    asn_cases: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    asn_dominant: dict[str, str] = {}  # ASN -> its dominant (most common) case

    for r in unique_rows:
        case = r.get("Erosion Case?", "").strip()
        asn = r.get("ASN", "").strip()
        company = r.get("Company Name", "").strip()
        if case:
            case_counts[case] += 1
        if asn and case:
            asn_cases[asn][case] += 1
            if company and asn not in asn_to_company:
                asn_to_company[asn] = company

    total = sum(case_counts.values())
    if total == 0:
        print("\n  No EROSION case data found.")
        return

    # Determine dominant case per ASN
    for asn, cases in asn_cases.items():
        asn_dominant[asn] = max(cases, key=cases.get)

    print()
    print("  " + "=" * 60)
    print("   EROSION Risk Distribution")
    print("  " + "=" * 60)

    # -- By IP -----------------------------------------------------------------
    print()
    print("   By IP")
    print("  " + "-" * 63)
    print(f"   {'Case':<6}{'Description':<42}{'IPs':>7}{'%':>8}")
    print("  " + "-" * 63)
    for case in sorted(case_counts.keys()):
        desc = EROSION_DESCRIPTIONS.get(case, "Unknown")
        count = case_counts[case]
        print(f"   {case:<6}{desc:<42}{count:>7,}{_pct(count, total):>8}")
    print(f"   {'':<6}{'':<42}{'─' * 7}")
    print(f"   {'Total':<48}{total:>7,}")

    # -- By ASN ----------------------------------------------------------------
    # Count how many ASNs fall dominantly under each case
    asn_case_counts: dict[str, int] = defaultdict(int)
    for asn, dominant in asn_dominant.items():
        asn_case_counts[dominant] += 1

    total_asns = len(asn_cases)

    print()
    print("   By ASN (classified by dominant case)")
    print("  " + "-" * 63)
    print(f"   {'Case':<6}{'Description':<42}{'ASNs':>7}{'%':>8}")
    print("  " + "-" * 63)
    for case in sorted(asn_case_counts.keys()):
        desc = EROSION_DESCRIPTIONS.get(case, "Unknown")
        count = asn_case_counts[case]
        print(f"   {case:<6}{desc:<42}{count:>7,}{_pct(count, total_asns):>8}")
    print(f"   {'':<6}{'':<42}{'─' * 7}")
    print(f"   {'Total':<48}{total_asns:>7,}")

    # Per-case ASN detail
    for case in sorted(case_counts.keys()):
        # ASNs that have IPs in this case, sorted by count
        asns_in_case = sorted(
            [(asn, cases[case]) for asn, cases in asn_cases.items() if cases.get(case, 0) > 0],
            key=lambda x: -x[1],
        )
        if not asns_in_case:
            continue

        top_n = _ask_top_n(f"ASNs in Case {case}")
        display = asns_in_case if top_n is None else asns_in_case[:top_n]

        desc = EROSION_DESCRIPTIONS.get(case, "")
        print()
        print(f"   Case {case} ASNs: {desc} (showing {len(display):,})")
        print("  " + "-" * 60)
        print(f"   {'Rank':<6}{'ASN':<12}{'Organization':<30}{'IPs in Case':>11}")
        print("  " + "-" * 60)
        for rank, (asn, count) in enumerate(display, 1):
            company = asn_to_company.get(asn, "")
            if len(company) > 28:
                company = company[:25] + "..."
            print(f"   {rank:<6}{asn:<12}{company:<30}{count:>11,}")

    print()
    print("  " + "=" * 60)


# ---------------------------------------------------------------------------
#  [5] ROA Coverage Analysis
# ---------------------------------------------------------------------------

def _roa_coverage_analysis():
    """Analyze ROA coverage and show top ASNs with/without ROA."""
    unique_rows = _load_unique_ips()
    if unique_rows is None:
        return

    asn_to_company: dict[str, str] = {}
    asn_roa: dict[str, dict[str, int]] = defaultdict(lambda: {"valid": 0, "none": 0})
    asn_maxlen_risk: dict[str, int] = defaultdict(int)
    asn_erosion: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for r in unique_rows:
        asn = r.get("ASN", "").strip()
        company = r.get("Company Name", "").strip()
        roa = r.get("ROA Return", "").strip()
        case = r.get("Erosion Case?", "").strip()
        if not asn:
            continue
        if company and asn not in asn_to_company:
            asn_to_company[asn] = company
        if roa == "Valid":
            asn_roa[asn]["valid"] += 1
        elif roa == "Not Valid":
            asn_roa[asn]["none"] += 1
        if case == "2":
            asn_maxlen_risk[asn] += 1
        if case:
            asn_erosion[asn][case] += 1

    total_valid = sum(v["valid"] for v in asn_roa.values())
    total_none = sum(v["none"] for v in asn_roa.values())
    total = total_valid + total_none

    print()
    print("  " + "=" * 60)
    print("   ROA Coverage Analysis")
    print("  " + "=" * 60)

    print()
    print("   Overall ROA Status")
    print("  " + "-" * 46)
    print(f"   Valid ROA:           {total_valid:>6,}   ({_pct(total_valid, total)})")
    print(f"   No ROA:             {total_none:>6,}   ({_pct(total_none, total)})")
    print(f"   Total IPs:          {total:>6,}")

    # Top ASNs without ROA
    asns_no_roa = sorted(
        [(asn, v["none"], v["valid"] + v["none"]) for asn, v in asn_roa.items() if v["none"] > 0],
        key=lambda x: -x[1],
    )

    top_n = _ask_top_n("ASNs without ROA")
    display = asns_no_roa if top_n is None else asns_no_roa[:top_n]

    print()
    print(f"   Top ASNs without ROA (showing {len(display):,})")
    print("  " + "-" * 60)
    print(f"   {'Rank':<6}{'ASN':<12}{'Organization':<28}{'No ROA':>7}  {'Total':>6}  {'EROSION Cases'}")
    print("  " + "-" * 60)
    for rank, (asn, no_roa, total_ips) in enumerate(display, 1):
        company = asn_to_company.get(asn, "")
        if len(company) > 26:
            company = company[:23] + "..."
        cases = asn_erosion.get(asn, {})
        case_str = "  ".join(f"Case {c}: {n}" for c, n in sorted(cases.items()))
        print(f"   {rank:<6}{asn:<12}{company:<28}{no_roa:>7}  {total_ips:>6}  {case_str}")

    # Top ASNs with valid ROA
    asns_valid = sorted(
        [(asn, v["valid"], v["valid"] + v["none"]) for asn, v in asn_roa.items() if v["valid"] > 0],
        key=lambda x: -x[1],
    )

    top_n2 = _ask_top_n("ASNs with valid ROA")
    display2 = asns_valid if top_n2 is None else asns_valid[:top_n2]

    print()
    print(f"   Top ASNs with Valid ROA (showing {len(display2):,})")
    print("  " + "-" * 60)
    print(f"   {'Rank':<6}{'ASN':<12}{'Organization':<28}{'ROA IPs':>7}  {'Total':>6}  {'MaxLen Risk':<28}{'EROSION Cases'}")
    print("  " + "-" * 60)
    for rank, (asn, valid, total_ips) in enumerate(display2, 1):
        company = asn_to_company.get(asn, "")
        if len(company) > 26:
            company = company[:23] + "..."
        ml_risk = asn_maxlen_risk.get(asn, 0)
        ml_str = f"{ml_risk} have MaxLen > prefix" if ml_risk else "All MaxLen = prefix"
        cases = asn_erosion.get(asn, {})
        case_str = "  ".join(f"Case {c}: {n}" for c, n in sorted(cases.items()))
        print(f"   {rank:<6}{asn:<12}{company:<28}{valid:>7}  {total_ips:>6}  {ml_str:<28}{case_str}")

    print()
    print("  " + "=" * 60)


# ---------------------------------------------------------------------------
#  [6] ASN Concentration Analysis
# ---------------------------------------------------------------------------

def _asn_concentration_analysis():
    """Analyze how concentrated GPU infrastructure is across ASNs."""
    unique_rows = _load_unique_ips()
    if unique_rows is None:
        return

    asn_to_company: dict[str, str] = {}
    asn_ips: dict[str, set] = defaultdict(set)
    asn_prefixes: dict[str, set] = defaultdict(set)
    asn_erosion: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    all_prefixes: set[str] = set()

    for r in unique_rows:
        asn = r.get("ASN", "").strip()
        company = r.get("Company Name", "").strip()
        ip = r.get("IP Addresses", "").strip()
        prefix = r.get("Range", "").strip()
        case = r.get("Erosion Case?", "").strip()
        if not asn or not ip:
            continue
        if company and asn not in asn_to_company:
            asn_to_company[asn] = company
        asn_ips[asn].add(ip)
        if prefix:
            asn_prefixes[asn].add(prefix)
            all_prefixes.add(prefix)
        if case:
            asn_erosion[asn][case] += 1

    total_asns = len(asn_ips)
    total_ips = sum(len(ips) for ips in asn_ips.values())
    total_prefixes = len(all_prefixes)

    print()
    print("  " + "=" * 60)
    print("   ASN Concentration Analysis")
    print("  " + "=" * 60)

    print()
    print("   Infrastructure Distribution")
    print("  " + "-" * 46)
    print(f"   Total unique ASNs:         {total_asns:>6,}")
    print(f"   Total unique IPs:          {total_ips:>6,}")
    print(f"   Total BGP prefixes:        {total_prefixes:>6,}")

    ranked = sorted(asn_ips.items(), key=lambda x: -len(x[1]))

    top_n = _ask_top_n("ASNs by IP count")
    display = ranked if top_n is None else ranked[:top_n]

    print()
    print(f"   Top ASNs by IP Count (showing {len(display):,})")
    print("  " + "-" * 60)
    print(f"   {'Rank':<6}{'ASN':<12}{'Organization':<24}{'IPs':>5}  {'% Total':>8}  {'Prefixes':>8}  {'EROSION Cases'}")
    print("  " + "-" * 100)
    for rank, (asn, ips) in enumerate(display, 1):
        company = asn_to_company.get(asn, "")
        if len(company) > 22:
            company = company[:19] + "..."
        n_ips = len(ips)
        n_pfx = len(asn_prefixes.get(asn, set()))
        cases = asn_erosion.get(asn, {})
        case_str = "  ".join(f"Case {c}: {n} IPs" for c, n in sorted(cases.items()))
        print(f"   {rank:<6}{asn:<12}{company:<24}{n_ips:>5}  {_pct(n_ips, total_ips):>8}  {n_pfx:>8}  {case_str}")

    # Concentration summary
    cumulative = 0
    thresholds = {5: 0, 10: 0, 20: 0}
    for i, (asn, ips) in enumerate(ranked, 1):
        cumulative += len(ips)
        if i in thresholds:
            thresholds[i] = cumulative

    single_ip_asns = sum(1 for ips in asn_ips.values() if len(ips) == 1)

    print()
    print("   Concentration Summary")
    print("  " + "-" * 46)
    for n, count in thresholds.items():
        if n <= total_asns:
            print(f"   Top {n} ASNs:     {count:>6,} IPs  ({_pct(count, total_ips)} of total)")
    print(f"   Single-IP ASNs: {single_ip_asns:>6,} ASNs ({_pct(single_ip_asns, total_asns)} of ASNs, {_pct(single_ip_asns, total_ips)} of IPs)")

    print()
    print("  " + "=" * 60)

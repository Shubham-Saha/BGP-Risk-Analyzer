"""Visualization package for BGP Risk Analyzer.

Generates research-quality charts from scan data, saving PNGs to
results/visualizations/<timestamp>/.
"""

from datetime import datetime, timezone

from config import CSV_FILE, RESULTS_DIR, UNIQUE_IPS_CSV_FILE, VAST_CSV_FILE

CHARTS_BASE = RESULTS_DIR / "visualizations"


def run_visualizations():
    """Generate all applicable charts in a timestamped subfolder."""
    from visualization.loader import (
        load_changes,
        load_scan_results,
        load_unique_ips,
        load_vast_results,
    )

    has_scan = CSV_FILE.exists()
    has_unique = UNIQUE_IPS_CSV_FILE.exists()
    has_vast = VAST_CSV_FILE.exists()

    if not has_scan and not has_unique:
        print("\n  No CSV data found. Run a scan first.\n")
        return

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S_UTC")
    charts_dir = CHARTS_BASE / timestamp
    charts_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n  Output folder: results/visualizations/{timestamp}/")

    generated = []

    # ── Chart 1: EROSION Exposure Timeline ────────────────────────────────
    if has_scan:
        from visualization.erosion_timeline import chart_erosion_timeline

        scan_rows = load_scan_results()
        if scan_rows:
            path = str(charts_dir / "1_erosion_timeline.png")
            if chart_erosion_timeline(scan_rows, path):
                generated.append("1_erosion_timeline.png")
                print("    [+] 1_erosion_timeline.png")
            else:
                print("    [-] 1_erosion_timeline.png — not enough crawl data")
        else:
            print("    [-] scan_results.csv is empty")

    # ── Chart 2: ASN Concentration Lorenz Curve ───────────────────────────
    if has_unique:
        from visualization.lorenz_curve import chart_lorenz_curve

        unique_rows = load_unique_ips()
        if unique_rows:
            path = str(charts_dir / "2_asn_lorenz_curve.png")
            if chart_lorenz_curve(unique_rows, path):
                generated.append("2_asn_lorenz_curve.png")
                print("    [+] 2_asn_lorenz_curve.png")
            else:
                print("    [-] 2_asn_lorenz_curve.png — not enough ASN data")

    # ── Chart 3: IP Hardware Turnover ─────────────────────────────────────
    change_rows = load_changes()
    if change_rows:
        from visualization.ip_turnover import chart_ip_turnover

        unique_rows = load_unique_ips() if has_unique else []
        vast_rows = load_vast_results() if has_vast else []

        path = str(charts_dir / "3_ip_hardware_turnover.png")
        if chart_ip_turnover(change_rows, unique_rows, vast_rows, path):
            generated.append("3_ip_hardware_turnover.png")
            print("    [+] 3_ip_hardware_turnover.png")
        else:
            print("    [-] 3_ip_hardware_turnover.png — not enough change data")
    else:
        print("    [-] No change data found (need 2+ crawls)")

    # ── Summary ───────────────────────────────────────────────────────────
    print(f"\n  Generated {len(generated)} chart(s) in results/visualizations/{timestamp}/")
    for name in generated:
        print(f"    - {name}")
    print()

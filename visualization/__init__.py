"""Visualization package for BGP Risk Analyzer.

Generates publication-quality charts from scan_results.csv and
prime_pod_results.csv, saving PNGs to results/visualizations/<timestamp>/.
"""

from datetime import datetime, timezone
from pathlib import Path

from config import CSV_FILE, PRIME_CSV_FILE, RESULTS_DIR

CHARTS_BASE = RESULTS_DIR / "visualizations"


def run_visualizations():
    """Generate all applicable charts in a timestamped subfolder."""
    from visualization.loader import load_bgp_data, load_merged_data, load_prime_data

    has_bgp = CSV_FILE.exists()
    has_prime = PRIME_CSV_FILE.exists()

    if not has_bgp and not has_prime:
        print("\n  No CSV data found. Run a scan first (options 1-5).\n")
        return

    # Create timestamped subfolder for this run
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S_UTC")
    CHARTS_DIR = CHARTS_BASE / timestamp
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)

    print(f"\n  Output folder: results/visualizations/{timestamp}/")

    generated = []
    merged = None  # will be loaded when needed for combined/research charts

    # ── BGP charts (1-6) ─────────────────────────────────────────────────
    if has_bgp:
        from visualization.bgp_charts import (
            chart_erosion_distribution,
            chart_maxlength_gap,
            chart_prefix_length_distribution,
            chart_roa_coverage,
            chart_vulnerability_by_company,
            chart_vulnerability_by_country,
        )

        bgp = load_bgp_data()
        if bgp.empty:
            print("  scan_results.csv is empty — skipping BGP charts.\n")
        else:
            print(f"\n  Loaded {len(bgp)} rows from scan_results.csv")

            charts = [
                ("1_case_distribution.png", chart_erosion_distribution),
                ("2_roa_coverage.png", chart_roa_coverage),
                ("3_vulnerability_by_company.png", chart_vulnerability_by_company),
                ("4_vulnerability_by_country.png", chart_vulnerability_by_country),
                ("5_prefix_length_distribution.png", chart_prefix_length_distribution),
                ("6_maxlength_gap.png", chart_maxlength_gap),
            ]
            for filename, fn in charts:
                path = str(CHARTS_DIR / filename)
                result = fn(bgp, path)
                if result:
                    generated.append(filename)
                    print(f"    [+] {filename}")
                else:
                    print(f"    [-] {filename} — not enough data")
    else:
        print("  scan_results.csv not found — skipping BGP charts (1-6).")

    # ── Prime charts (7-8) ───────────────────────────────────────────────
    if has_prime:
        from visualization.prime_charts import (
            chart_gpu_pricing,
            chart_provider_geography,
        )

        prime = load_prime_data()
        if prime.empty:
            print("  prime_pod_results.csv is empty — skipping Prime charts.\n")
        else:
            print(f"  Loaded {len(prime)} rows from prime_pod_results.csv")

            charts = [
                ("7_gpu_pricing.png", chart_gpu_pricing),
                ("8_provider_geography.png", chart_provider_geography),
            ]
            for filename, fn in charts:
                path = str(CHARTS_DIR / filename)
                result = fn(prime, path)
                if result:
                    generated.append(filename)
                    print(f"    [+] {filename}")
                else:
                    print(f"    [-] {filename} — not enough data")
    else:
        print("  prime_pod_results.csv not found — skipping Prime charts (7-8).")

    # ── Combined charts (9-11) ──────────────────────────────────────────
    if has_bgp and has_prime:
        from visualization.combined_charts import (
            chart_erosion_by_provider,
            chart_erosion_by_region,
            chart_ip_concentration,
        )

        merged = load_merged_data()  # cached for research charts too
        if merged.empty:
            print("  No matching IPs between CSVs — skipping combined charts.\n")
        else:
            print(f"  Merged data: {len(merged)} rows")

            charts = [
                ("9_erosion_by_provider.png", chart_erosion_by_provider),
                ("10_erosion_by_region.png", chart_erosion_by_region),
                ("11_ip_concentration_risk.png", chart_ip_concentration),
            ]
            for filename, fn in charts:
                path = str(CHARTS_DIR / filename)
                result = fn(merged, path)
                if result:
                    generated.append(filename)
                    print(f"    [+] {filename}")
                else:
                    print(f"    [-] {filename} — not enough data")
    elif has_bgp or has_prime:
        print("  Both CSVs needed for combined charts (9-11) — skipping.")

    # ── Research charts (12-19) ───────────────────────────────────────────
    if has_bgp and has_prime:
        from visualization.research_charts import (
            chart_attack_surface,
            chart_case2_deep_dive,
            chart_enumeration_funnel,
            chart_geographic_risk,
            chart_gpu_vulnerability,
            chart_provider_security,
            chart_provider_security_by_ip,
            chart_provider_vulnerability,
            chart_shared_prefixes,
        )

        if merged is None or merged.empty:
            merged = load_merged_data()

        if merged.empty:
            print("  No matching IPs — skipping research charts (12-17).\n")
        else:
            print(f"  Research charts: using {len(merged)} merged rows")

            charts = [
                ("12_attack_surface.png", chart_attack_surface),
                ("13_provider_security.png", chart_provider_security),
                ("14_gpu_vulnerability.png", chart_gpu_vulnerability),
                ("15_geographic_risk.png", chart_geographic_risk),
                ("16_case2_deep_dive.png", chart_case2_deep_dive),
                ("17_shared_prefixes.png", chart_shared_prefixes),
                ("18_provider_security_by_ip.png", chart_provider_security_by_ip),
                ("19_enumeration_funnel.png", chart_enumeration_funnel),
                ("20_provider_vulnerability.png", chart_provider_vulnerability),
            ]
            for filename, fn in charts:
                path = str(CHARTS_DIR / filename)
                result = fn(merged, path)
                if result:
                    generated.append(filename)
                    print(f"    [+] {filename}")
                else:
                    print(f"    [-] {filename} — not enough data")
    elif has_bgp or has_prime:
        print("  Both CSVs needed for research charts (12-18) — skipping.")

    # ── Summary ──────────────────────────────────────────────────────────
    print(f"\n  Generated {len(generated)} chart(s) in results/visualizations/{timestamp}/")
    if generated:
        for name in generated:
            print(f"    - {name}")
    print()

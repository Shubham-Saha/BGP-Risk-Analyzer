"""Chart 1: EROSION Exposure Timeline — how the attack surface evolves across crawls."""

from collections import defaultdict

import matplotlib.pyplot as plt
import numpy as np

from visualization.style import CASE_COLORS, CASE_LABELS, apply_style


def chart_erosion_timeline(scan_rows: list[dict], save_path: str) -> bool:
    """Stacked area chart: % of IPs in each EROSION case per crawl date.

    Uses scan_results.csv which has one row per IP per crawl (duplicate IPs
    across dates). Groups by date, computes case distribution as percentages.
    """
    if not scan_rows:
        return False

    # Group by date → case counts
    date_cases: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
    for r in scan_rows:
        dt = r.get("Last accessed", "")[:10]
        case_str = r.get("Erosion Case?", "").strip()
        if dt and case_str and case_str.isdigit():
            date_cases[dt][int(case_str)] += 1

    if len(date_cases) < 2:
        return False

    dates = sorted(date_cases.keys())
    cases = [1, 2, 3, 4]

    # Build percentage arrays
    pct_data = {c: [] for c in cases}
    totals = []
    for dt in dates:
        total = sum(date_cases[dt].get(c, 0) for c in cases)
        totals.append(total)
        for c in cases:
            pct = (date_cases[dt].get(c, 0) / total * 100) if total > 0 else 0
            pct_data[c].append(pct)

    x = np.arange(len(dates))

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 9), height_ratios=[3, 1])

    # Top: stacked area chart (percentages)
    bottom = np.zeros(len(dates))
    for c in cases:
        vals = np.array(pct_data[c])
        ax1.fill_between(x, bottom, bottom + vals,
                         color=CASE_COLORS[c], alpha=0.8,
                         label=CASE_LABELS[c])
        # Add percentage label at midpoint of each area on last date
        mid = bottom[-1] + vals[-1] / 2
        if vals[-1] > 4:  # only label if area is wide enough
            ax1.annotate(f"{vals[-1]:.1f}%",
                         xy=(x[-1], mid),
                         xytext=(10, 0), textcoords="offset points",
                         fontsize=9, va="center", fontweight="bold",
                         color=CASE_COLORS[c])
        bottom += vals

    ax1.set_xlim(x[0], x[-1])
    ax1.set_ylim(0, 100)
    ax1.set_xticks(x)
    ax1.set_xticklabels(dates, rotation=30, ha="right", fontsize=9)
    ax1.set_ylabel("% of IPs", fontsize=11)
    ax1.set_title("EROSION Attack Surface Evolution Across Crawls",
                   fontsize=14, fontweight="bold", pad=12)
    ax1.legend(loc="upper left", fontsize=9, framealpha=0.9)
    ax1.grid(axis="y", linestyle="--", alpha=0.3)

    # Bottom: bar chart showing total IPs scanned per date
    bar_colors = []
    for dt in dates:
        # Color by dominant case
        dominant = max(cases, key=lambda c: date_cases[dt].get(c, 0))
        bar_colors.append(CASE_COLORS[dominant])

    ax2.bar(x, totals, color="#3498db", alpha=0.7, width=0.6)
    for i, t in enumerate(totals):
        ax2.text(i, t + max(totals) * 0.02, str(t),
                 ha="center", va="bottom", fontsize=9, fontweight="bold")

    ax2.set_xlim(x[0] - 0.5, x[-1] + 0.5)
    ax2.set_xticks(x)
    ax2.set_xticklabels(dates, rotation=30, ha="right", fontsize=9)
    ax2.set_ylabel("IPs Scanned", fontsize=11)
    ax2.set_xlabel("Crawl Date", fontsize=11)
    ax2.grid(axis="y", linestyle="--", alpha=0.3)

    fig.tight_layout()
    fig.savefig(save_path, dpi=200, bbox_inches="tight")
    plt.close(fig)
    return True

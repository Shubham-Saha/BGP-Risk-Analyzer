"""Chart 3: IP Hardware Turnover Analysis.

Shows how frequently hardware specs change for an IP, which fields change
most, and correlates turnover with EROSION case classification.
Generates a multi-panel figure for research discussion.
"""

from collections import Counter, defaultdict

import matplotlib.pyplot as plt
import numpy as np

from visualization.style import CASE_COLORS, CASE_LABELS_SHORT


# Hardware-related fields vs BGP/network fields
HARDWARE_FIELDS = {
    "GPU Type", "Num GPUs", "GPU RAM (GB)", "CPU Name",
    "CPU Cores", "RAM (GB)", "Disk (GB)",
}

NETWORK_FIELDS = {
    "ASN", "Prefix", "ROA Return", "Erosion Case?",
}

INFRA_FIELDS = {
    "Price per Hour", "Reliability", "Static IP",
    "Total Machines at IP", "Internet Down (Mbps)", "Internet Up (Mbps)",
}


def chart_ip_turnover(
    change_rows: list[dict],
    unique_rows: list[dict],
    vast_rows: list[dict],
    save_path: str,
) -> bool:
    """Multi-panel figure analyzing hardware turnover at IP level.

    Panel A: Field change frequency — which specs change most
    Panel B: Hardware change rate per IP (histogram) vs EROSION case
    Panel C: When do changes happen? (changes over time)
    Panel D: IPs by change intensity vs EROSION case (scatter-like)
    """
    if not change_rows:
        return False

    # ── Data prep ──────────────────────────────────────────────────────────

    # IP → EROSION case lookup from unique_rows
    ip_to_case: dict[str, int] = {}
    for r in unique_rows:
        ip = r.get("IP Addresses", "").strip()
        case_str = r.get("Erosion Case?", "").strip()
        if ip and case_str and case_str.isdigit():
            ip_to_case[ip] = int(case_str)

    # Also get case from vast_rows for IPs not in unique_rows
    for r in vast_rows:
        ip = r.get("IP Address", "").strip()
        case_str = r.get("Erosion Case?", "").strip()
        if ip and case_str and case_str.isdigit() and ip not in ip_to_case:
            ip_to_case[ip] = int(case_str)

    # Count changes per field
    field_counts: dict[str, int] = Counter()
    # Count hardware changes per IP
    ip_hw_changes: dict[str, int] = defaultdict(int)
    # Track change timestamps
    change_dates: dict[str, int] = Counter()
    # Total changes per IP
    ip_total_changes: dict[str, int] = defaultdict(int)

    for r in change_rows:
        ip = (r.get("IP Address", "") or r.get("Pod ID", "") or r.get("_ip", "")).strip()
        field = r.get("Field Changed", "").strip()
        ts = r.get("Current Scan Timestamp", "")[:10]

        if field:
            field_counts[field] += 1
        if ip and field in HARDWARE_FIELDS:
            ip_hw_changes[ip] += 1
        if ip and field:
            ip_total_changes[ip] += 1
        if ts:
            change_dates[ts] += 1

    # Count total IPs (from vast_rows)
    all_ips = set(r.get("IP Address", "").strip() for r in vast_rows
                  if r.get("IP Address", "").strip())
    ips_with_hw_changes = set(ip_hw_changes.keys())
    ips_without_changes = all_ips - set(ip_total_changes.keys())

    # ── Figure ─────────────────────────────────────────────────────────────

    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle("IP Hardware Turnover Analysis",
                 fontsize=16, fontweight="bold", y=0.98)

    # ── Panel A: Field change frequency ────────────────────────────────────
    ax = axes[0, 0]
    top_fields = field_counts.most_common(12)
    if top_fields:
        fields_sorted = list(reversed(top_fields))  # horizontal bar, bottom to top
        labels = [f[0] for f in fields_sorted]
        values = [f[1] for f in fields_sorted]
        colors = []
        for f in labels:
            if f in HARDWARE_FIELDS:
                colors.append("#e74c3c")
            elif f in NETWORK_FIELDS:
                colors.append("#3498db")
            else:
                colors.append("#95a5a6")

        bars = ax.barh(range(len(labels)), values, color=colors, alpha=0.8)
        ax.set_yticks(range(len(labels)))
        ax.set_yticklabels(labels, fontsize=9)
        for i, v in enumerate(values):
            ax.text(v + max(values) * 0.01, i, f"{v:,}",
                    va="center", fontsize=9, fontweight="bold")

        # Legend
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor="#e74c3c", alpha=0.8, label="Hardware"),
            Patch(facecolor="#3498db", alpha=0.8, label="Network/BGP"),
            Patch(facecolor="#95a5a6", alpha=0.8, label="Infrastructure"),
        ]
        ax.legend(handles=legend_elements, loc="lower right", fontsize=9)

    ax.set_xlabel("Total Change Records", fontsize=10)
    ax.set_title("(A) Which Fields Change Most?", fontsize=12, fontweight="bold")
    ax.grid(axis="x", linestyle="--", alpha=0.3)

    # ── Panel B: Hardware changes per IP, colored by EROSION case ──────────
    ax = axes[0, 1]

    # Bin IPs by hardware change count
    case_bins: dict[int, list[int]] = {1: [], 2: [], 3: [], 4: []}
    for ip, count in ip_hw_changes.items():
        case = ip_to_case.get(ip)
        if case in case_bins:
            case_bins[case].append(count)

    # Also add zero-change IPs
    for ip in all_ips:
        if ip not in ip_hw_changes:
            case = ip_to_case.get(ip)
            if case in case_bins:
                case_bins[case].append(0)

    # Create bins
    max_changes = max((max(v) if v else 0 for v in case_bins.values()), default=10)
    bin_edges = [0, 1, 3, 5, 10, 20, max(50, max_changes + 1)]
    bin_labels = ["0", "1-2", "3-4", "5-9", "10-19", "20+"]

    bar_width = 0.2
    x_pos = np.arange(len(bin_labels))

    for i, case in enumerate([1, 2, 3, 4]):
        counts_per_bin = np.histogram(case_bins[case], bins=bin_edges)[0]
        ax.bar(x_pos + i * bar_width, counts_per_bin, bar_width,
               color=CASE_COLORS[case], alpha=0.8,
               label=CASE_LABELS_SHORT[case])

    ax.set_xticks(x_pos + 1.5 * bar_width)
    ax.set_xticklabels(bin_labels, fontsize=9)
    ax.set_xlabel("Hardware Changes per IP", fontsize=10)
    ax.set_ylabel("Number of IPs", fontsize=10)
    ax.set_title("(B) Hardware Change Intensity by EROSION Case", fontsize=12, fontweight="bold")
    ax.legend(fontsize=8, ncol=2)
    ax.grid(axis="y", linestyle="--", alpha=0.3)

    # ── Panel C: Changes over time ─────────────────────────────────────────
    ax = axes[1, 0]

    if change_dates:
        # Split by field category
        hw_by_date: dict[str, int] = Counter()
        net_by_date: dict[str, int] = Counter()
        infra_by_date: dict[str, int] = Counter()

        for r in change_rows:
            field = r.get("Field Changed", "").strip()
            ts = r.get("Current Scan Timestamp", "")[:10]
            if not ts:
                continue
            if field in HARDWARE_FIELDS:
                hw_by_date[ts] += 1
            elif field in NETWORK_FIELDS:
                net_by_date[ts] += 1
            else:
                infra_by_date[ts] += 1

        dates = sorted(set(hw_by_date) | set(net_by_date) | set(infra_by_date))
        x = np.arange(len(dates))

        hw_vals = [hw_by_date.get(d, 0) for d in dates]
        net_vals = [net_by_date.get(d, 0) for d in dates]
        infra_vals = [infra_by_date.get(d, 0) for d in dates]

        ax.bar(x, hw_vals, 0.6, label="Hardware", color="#e74c3c", alpha=0.8)
        ax.bar(x, infra_vals, 0.6, bottom=hw_vals, label="Infrastructure", color="#95a5a6", alpha=0.8)
        bottom2 = [h + i for h, i in zip(hw_vals, infra_vals)]
        ax.bar(x, net_vals, 0.6, bottom=bottom2, label="Network/BGP", color="#3498db", alpha=0.8)

        ax.set_xticks(x)
        ax.set_xticklabels(dates, rotation=30, ha="right", fontsize=9)
        ax.legend(fontsize=9)

    ax.set_xlabel("Date", fontsize=10)
    ax.set_ylabel("Change Records", fontsize=10)
    ax.set_title("(C) When Do Changes Happen?", fontsize=12, fontweight="bold")
    ax.grid(axis="y", linestyle="--", alpha=0.3)

    # ── Panel D: Summary stats box ─────────────────────────────────────────
    ax = axes[1, 1]
    ax.axis("off")

    total_ips = len(all_ips)
    ips_changed = len(set(ip_total_changes.keys()) & all_ips)
    ips_hw_changed = len(ips_with_hw_changes & all_ips)
    pct_changed = ips_changed / total_ips * 100 if total_ips else 0
    pct_hw = ips_hw_changed / total_ips * 100 if total_ips else 0

    # Average hardware changes for IPs that did change
    avg_hw = (sum(ip_hw_changes.values()) / len(ip_hw_changes)) if ip_hw_changes else 0

    # EROSION case breakdown for changed vs unchanged IPs
    changed_cases: dict[int, int] = Counter()
    unchanged_cases: dict[int, int] = Counter()
    for ip in all_ips:
        case = ip_to_case.get(ip)
        if case:
            if ip in ip_total_changes:
                changed_cases[case] += 1
            else:
                unchanged_cases[case] += 1

    summary_text = (
        f"Hardware Turnover Summary\n"
        f"{'─' * 40}\n\n"
        f"Total IPs monitored:       {total_ips:,}\n"
        f"IPs with any change:       {ips_changed:,}  ({pct_changed:.1f}%)\n"
        f"IPs with hardware change:  {ips_hw_changed:,}  ({pct_hw:.1f}%)\n"
        f"Avg HW changes/IP:         {avg_hw:.1f}\n\n"
        f"Changed IPs by EROSION Case:\n"
    )
    for c in [1, 2, 3, 4]:
        ch = changed_cases.get(c, 0)
        unch = unchanged_cases.get(c, 0)
        total_c = ch + unch
        ch_pct = ch / total_c * 100 if total_c else 0
        summary_text += f"  {CASE_LABELS_SHORT[c]}: {ch}/{total_c} changed ({ch_pct:.0f}%)\n"

    summary_text += (
        f"\nTop changing hardware fields:\n"
    )
    hw_only = [(f, c) for f, c in field_counts.most_common() if f in HARDWARE_FIELDS]
    for f, c in hw_only[:5]:
        summary_text += f"  {f}: {c:,}\n"

    ax.text(0.05, 0.95, summary_text,
            transform=ax.transAxes, fontsize=11,
            verticalalignment="top", fontfamily="monospace",
            bbox=dict(boxstyle="round,pad=0.5", facecolor="#f8f9fa",
                      edgecolor="#2c3e50", alpha=0.9))
    ax.set_title("(D) Key Findings", fontsize=12, fontweight="bold")

    fig.tight_layout(rect=[0, 0, 1, 0.96])
    fig.savefig(save_path, dpi=200, bbox_inches="tight")
    plt.close(fig)
    return True

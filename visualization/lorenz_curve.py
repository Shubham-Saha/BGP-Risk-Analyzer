"""Chart 2: ASN Concentration Lorenz Curve — infrastructure inequality."""

from collections import defaultdict

import matplotlib.pyplot as plt
import numpy as np

from visualization.style import apply_style


def _gini_coefficient(values: list[int]) -> float:
    """Compute Gini coefficient from a list of non-negative values."""
    if not values or sum(values) == 0:
        return 0.0
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    total = sum(sorted_vals)
    cum = 0.0
    gini_sum = 0.0
    for i, v in enumerate(sorted_vals):
        cum += v
        gini_sum += (2 * (i + 1) - n - 1) * v
    return gini_sum / (n * total)


def chart_lorenz_curve(unique_rows: list[dict], save_path: str) -> bool:
    """Lorenz curve: cumulative % of ASNs vs cumulative % of IPs.

    Shows how concentrated GPU infrastructure is across ASNs.
    A perfectly equal distribution would follow the diagonal.
    The further the curve bows, the more concentrated.
    """
    if not unique_rows:
        return False

    # Count IPs per ASN
    asn_ips: dict[str, int] = defaultdict(int)
    for r in unique_rows:
        asn = r.get("ASN", "").strip()
        ip = r.get("IP Addresses", "").strip()
        if asn and ip:
            asn_ips[asn] += 1

    if len(asn_ips) < 3:
        return False

    # Sort ASNs by IP count (ascending for Lorenz curve)
    counts = sorted(asn_ips.values())
    n = len(counts)
    total_ips = sum(counts)

    # Build Lorenz curve points
    cum_asn = [0.0]
    cum_ips = [0.0]
    running = 0
    for i, c in enumerate(counts):
        running += c
        cum_asn.append((i + 1) / n * 100)
        cum_ips.append(running / total_ips * 100)

    gini = _gini_coefficient(counts)

    fig, ax = plt.subplots(figsize=(9, 8))

    # Equality line
    ax.plot([0, 100], [0, 100], "k--", linewidth=1, alpha=0.5, label="Perfect equality")

    # Lorenz curve
    ax.fill_between(cum_asn, cum_ips, [x for x in cum_asn],
                     color="#e74c3c", alpha=0.15)
    ax.plot(cum_asn, cum_ips, color="#e74c3c", linewidth=2.5,
            label=f"GPU IP distribution (Gini = {gini:.3f})")

    # Key annotations — mark the concentration milestones
    # Find: top 5%, top 10%, top 20% of ASNs
    milestones = [(5, None), (10, None), (20, None)]
    desc_counts = sorted(asn_ips.values(), reverse=True)
    for pct_idx in range(len(milestones)):
        target_pct = milestones[pct_idx][0]
        n_asns = max(1, int(n * target_pct / 100))
        ip_sum = sum(desc_counts[:n_asns])
        ip_pct = ip_sum / total_ips * 100
        milestones[pct_idx] = (target_pct, ip_pct)

    # Annotate milestones on the curve
    for asn_pct, ip_pct in milestones:
        # Find closest point on Lorenz curve (from the right side)
        x_pos = 100 - asn_pct  # Lorenz curve is ascending, so top X% starts from right
        # Find the actual y value at this x
        for i in range(len(cum_asn)):
            if cum_asn[i] >= x_pos:
                y_val = cum_ips[i]
                break
        else:
            y_val = ip_pct

        ax.annotate(
            f"Top {asn_pct}% ASNs → {ip_pct:.0f}% of IPs",
            xy=(x_pos, y_val),
            xytext=(x_pos - 25, y_val - 8),
            fontsize=9, fontweight="bold",
            arrowprops=dict(arrowstyle="->", color="#2c3e50", lw=1.2),
            bbox=dict(boxstyle="round,pad=0.3", facecolor="white",
                      edgecolor="#2c3e50", alpha=0.9),
        )

    # Gini coefficient annotation
    ax.text(
        15, 85,
        f"Gini Coefficient: {gini:.3f}\n"
        f"{n} ASNs hosting {total_ips:,} IPs\n"
        f"Single-IP ASNs: {sum(1 for c in counts if c == 1)}",
        fontsize=11, fontweight="bold",
        bbox=dict(boxstyle="round,pad=0.5", facecolor="#ecf0f1",
                  edgecolor="#2c3e50", alpha=0.9),
        verticalalignment="top",
    )

    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.set_xlabel("Cumulative % of ASNs (smallest to largest)", fontsize=12)
    ax.set_ylabel("Cumulative % of GPU IPs", fontsize=12)
    ax.set_title("GPU Infrastructure Concentration:\nASN Lorenz Curve",
                  fontsize=14, fontweight="bold", pad=12)
    ax.legend(loc="upper left", fontsize=10, framealpha=0.9)
    ax.grid(True, linestyle="--", alpha=0.3)
    ax.set_aspect("equal")

    fig.tight_layout()
    fig.savefig(save_path, dpi=200, bbox_inches="tight")
    plt.close(fig)
    return True

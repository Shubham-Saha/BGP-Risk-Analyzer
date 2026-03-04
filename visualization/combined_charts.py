"""Charts that cross-reference BGP and Prime Intellect data."""

import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import pandas as pd

from visualization.style import CASE_COLORS, CASE_LABELS, CASE_LABELS_SHORT, apply_style


def chart_erosion_by_provider(df: pd.DataFrame, out: str) -> str:
    """Chart 9: Stacked bar — Provider × BGP hijack vulnerability case."""
    subset = df[["Provider Type", "Erosion Case?"]].dropna()
    if subset.empty:
        return ""

    pivot = subset.groupby(["Provider Type", "Erosion Case?"]).size().unstack(fill_value=0)

    fig, ax = plt.subplots(figsize=(max(8, len(pivot) * 1.2), 6))
    bottom = np.zeros(len(pivot))
    for case in sorted(pivot.columns):
        vals = pivot[case].values
        ax.bar(
            pivot.index, vals, bottom=bottom,
            label=CASE_LABELS_SHORT.get(int(case), f"Case {int(case)}"),
            color=CASE_COLORS.get(int(case), "#999"),
        )
        bottom += vals

    ax.legend(fontsize=9)
    apply_style(fig, ax, title="BGP Hijack Vulnerability by GPU Provider", ylabel="Pod Count")
    ax.set_xticks(range(len(pivot.index)))
    ax.set_xticklabels(pivot.index, rotation=45, ha="right")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


def chart_erosion_by_region(df: pd.DataFrame, out: str) -> str:
    """Chart 10: Heatmap — Region × BGP hijack vulnerability case count."""
    if "AvailRegion" not in df.columns:
        return ""

    subset = df[["AvailRegion", "Erosion Case?"]].dropna()
    subset = subset[subset["AvailRegion"] != ""]
    if subset.empty:
        return ""

    pivot = subset.groupby(["AvailRegion", "Erosion Case?"]).size().unstack(fill_value=0)
    # Ensure all 4 cases present as columns
    for c in (1, 2, 3, 4):
        if c not in pivot.columns:
            pivot[c] = 0
    pivot = pivot[[c for c in sorted(pivot.columns)]]

    fig, ax = plt.subplots(figsize=(8, max(4, len(pivot) * 0.5)))
    im = ax.imshow(pivot.values, cmap="YlOrRd", aspect="auto")

    ax.set_xticks(range(pivot.shape[1]))
    ax.set_xticklabels([CASE_LABELS_SHORT.get(int(c), f"Case {int(c)}") for c in pivot.columns],
                       rotation=45, ha="right", fontsize=9)
    ax.set_yticks(range(pivot.shape[0]))
    ax.set_yticklabels(pivot.index, fontsize=10)

    # Annotate cells
    for i in range(pivot.shape[0]):
        for j in range(pivot.shape[1]):
            val = pivot.values[i, j]
            if val > 0:
                ax.text(j, i, str(int(val)), ha="center", va="center",
                        fontsize=11, fontweight="bold",
                        color="white" if val > pivot.values.max() * 0.6 else "black")

    fig.colorbar(im, ax=ax, label="Count", shrink=0.8)
    ax.set_title("BGP Hijack Vulnerability by Region", fontsize=14, fontweight="bold", pad=12)
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


def chart_ip_concentration(df: pd.DataFrame, out: str) -> str:
    """Chart 11: IP Concentration Risk — GPU configs sharing the same IP.

    Shows how many distinct GPU configurations (offerings) map to each
    unique IP address, highlighting that a single BGP hijack on that
    prefix disrupts all of them.
    """
    required = ["Pod IP", "GPU Count", "Erosion Case?"]
    if not all(c in df.columns for c in required):
        return ""

    subset = df[df["Pod IP"].notna() & (df["Pod IP"] != "")].copy()
    if subset.empty:
        return ""

    # Ensure GPU Count is numeric for sorting
    subset["GPU Count"] = pd.to_numeric(subset["GPU Count"], errors="coerce")

    # Build per-IP summary: count of configs, list of GPU counts, erosion case
    groups = subset.groupby("Pod IP").agg(
        num_configs=("GPU Count", "nunique"),
        gpu_configs=("GPU Count", lambda x: sorted(x.dropna().unique().astype(int))),
        erosion=("Erosion Case?", "first"),
        provider=("Provider Type", "first"),
        datacenter=("AvailDataCenter", "first") if "AvailDataCenter" in subset.columns
                   else ("Provider Type", "first"),
    ).reset_index()

    # Use datacenter if available, otherwise provider
    if "AvailDataCenter" in subset.columns:
        dc_col = subset.groupby("Pod IP")["AvailDataCenter"].first().reset_index()
        groups = groups.merge(dc_col, on="Pod IP", how="left", suffixes=("", "_dc"))
        if "AvailDataCenter_dc" in groups.columns:
            groups["datacenter"] = groups["AvailDataCenter_dc"]

    # Also get the BGP prefix for each IP
    if "Range" in df.columns:
        prefix_col = df.groupby("Pod IP")["Range"].first().reset_index()
        groups = groups.merge(prefix_col, on="Pod IP", how="left")
    elif "Prefix" in df.columns:
        prefix_col = df.groupby("Pod IP")["Prefix"].first().reset_index()
        groups = groups.merge(prefix_col, on="Pod IP", how="left")
        groups.rename(columns={"Prefix": "Range"}, inplace=True)

    # Sort by number of configs descending, then by provider
    groups = groups.sort_values(["num_configs", "provider"], ascending=[False, True])

    if groups.empty:
        return ""

    # Build labels: "IP (datacenter / provider)\nPrefix: x.x.x.x/24"
    labels = []
    for _, row in groups.iterrows():
        dc = row.get("datacenter", row.get("AvailDataCenter", ""))
        prov = row.get("provider", "")
        prefix = row.get("Range", "")
        label = f"{row['Pod IP']}\n({dc} / {prov})"
        if prefix:
            label += f"\n{prefix}"
        labels.append(label)

    # Colors based on vulnerability case
    colors = [CASE_COLORS.get(int(e), "#999") if pd.notna(e) else "#999"
              for e in groups["erosion"]]

    fig, ax = plt.subplots(figsize=(max(10, len(groups) * 0.8), 7))
    bars = ax.barh(range(len(groups)), groups["num_configs"], color=colors, edgecolor="white")

    # Annotate each bar with the GPU config list
    for i, (bar, row) in enumerate(zip(bars, groups.itertuples())):
        configs = row.gpu_configs
        config_str = ", ".join(f"x{int(c)}" for c in configs)
        # Place text inside or outside bar depending on width
        if bar.get_width() >= 2:
            ax.text(bar.get_width() - 0.1, bar.get_y() + bar.get_height() / 2,
                    config_str, ha="right", va="center", fontsize=9,
                    fontweight="bold", color="white")
        else:
            ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height() / 2,
                    config_str, ha="left", va="center", fontsize=9, fontweight="bold")

    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=8)
    ax.invert_yaxis()

    # Legend for vulnerability cases
    from matplotlib.patches import Patch
    legend_handles = [
        Patch(facecolor=CASE_COLORS[c], label=CASE_LABELS_SHORT[c])
        for c in sorted(CASE_COLORS)
        if c in groups["erosion"].dropna().astype(int).values
    ]
    if legend_handles:
        ax.legend(handles=legend_handles, fontsize=8, loc="lower right")

    apply_style(fig, ax,
                title="IP Concentration Risk: GPU Configurations per Shared IP",
                xlabel="Number of Distinct GPU Configurations")
    ax.set_ylabel("")

    fig.tight_layout()
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out

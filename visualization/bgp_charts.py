"""Charts derived from BGP scan data (scan_results.csv)."""

import matplotlib
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd

from visualization.style import (
    CASE_COLORS,
    CASE_LABELS,
    CASE_LABELS_SHORT,
    ROA_COLORS,
    apply_style,
)


def chart_erosion_distribution(df: pd.DataFrame, out: str) -> str:
    """Chart 1: Donut chart of BGP hijacking vulnerability case distribution."""
    counts = df["Erosion Case?"].dropna().astype(int).value_counts().sort_index()
    if counts.empty:
        return ""

    labels = [CASE_LABELS_SHORT.get(c, f"Case {c}") for c in counts.index]
    colors = [CASE_COLORS.get(c, "#999") for c in counts.index]
    total = sum(counts.values)

    old_rc = matplotlib.rcParams.copy()
    matplotlib.rcParams["font.family"] = "serif"
    matplotlib.rcParams["font.serif"] = ["Times New Roman"]

    try:
        fig, ax = plt.subplots(figsize=(10, 7))
        wedges, _, autotexts = ax.pie(
            counts.values,
            labels=[""] * len(counts),  # empty labels — legend used instead
            colors=colors,
            autopct=lambda p: f"{int(round(p * total / 100))} IPs",
            startangle=140,
            pctdistance=0.75,
            wedgeprops=dict(width=0.4),
        )
        for t in autotexts:
            t.set_fontsize(11)
            t.set_fontweight("bold")

        # Use a legend instead of inline labels to avoid clipping
        ax.legend(
            wedges, labels,
            title="BGP Hijacking Case",
            loc="upper left",
            bbox_to_anchor=(0.75, 1.0),
            fontsize=10,
        )

        ax.set_title("Susceptibility to BGP Hijacking — Case Distribution",
                     fontsize=14, fontweight="bold", pad=20)
        fig.subplots_adjust(left=0.05, right=0.65, top=0.90)
        fig.savefig(out, dpi=150, bbox_inches="tight")
        plt.close(fig)
    finally:
        matplotlib.rcParams.update(old_rc)

    return out


def chart_roa_coverage(df: pd.DataFrame, out: str) -> str:
    """Chart 2: Horizontal bar chart of ROA Valid vs Not Valid."""
    counts = df["ROA Return"].value_counts()
    if counts.empty:
        return ""

    fig, ax = plt.subplots(figsize=(8, 4))
    bars = ax.barh(
        counts.index,
        counts.values,
        color=[ROA_COLORS.get(k, "#999") for k in counts.index],
        edgecolor="white",
    )
    for bar, val in zip(bars, counts.values):
        ax.text(bar.get_width() + 0.2, bar.get_y() + bar.get_height() / 2,
                str(val), va="center", fontsize=11, fontweight="bold")

    apply_style(fig, ax, title="ROA Coverage", xlabel="Count")
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


def chart_vulnerability_by_company(df: pd.DataFrame, out: str) -> str:
    """Chart 3: Stacked horizontal bar — Company × hijack vulnerability case."""
    cases = sorted(df["Erosion Case?"].dropna().unique())
    if not len(cases):
        return ""

    pivot = df.groupby(["Company Name", "Erosion Case?"]).size().unstack(fill_value=0)
    pivot = pivot.sort_values(by=pivot.columns.tolist(), ascending=True)

    fig, ax = plt.subplots(figsize=(10, max(4, len(pivot) * 0.5)))
    left = np.zeros(len(pivot))
    for case in sorted(pivot.columns):
        vals = pivot[case].values
        ax.barh(
            pivot.index, vals, left=left,
            label=CASE_LABELS_SHORT.get(int(case), f"Case {int(case)}"),
            color=CASE_COLORS.get(int(case), "#999"),
        )
        left += vals

    ax.legend(loc="lower right", fontsize=9)
    apply_style(fig, ax, title="BGP Hijack Susceptibility by Company / ASN", xlabel="IP Count")
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


def chart_vulnerability_by_country(df: pd.DataFrame, out: str) -> str:
    """Chart 4: Stacked bar — Country × hijack vulnerability case."""
    if "Country" not in df.columns or df["Country"].dropna().empty:
        return ""

    pivot = df.groupby(["Country", "Erosion Case?"]).size().unstack(fill_value=0)
    pivot = pivot.sort_values(by=pivot.columns.tolist(), ascending=False)

    fig, ax = plt.subplots(figsize=(max(6, len(pivot) * 0.8), 6))
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
    apply_style(fig, ax, title="BGP Hijack Susceptibility by Country", ylabel="IP Count")
    ax.set_xticks(range(len(pivot.index)))
    ax.set_xticklabels(pivot.index, rotation=45, ha="right")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


def chart_prefix_length_distribution(df: pd.DataFrame, out: str) -> str:
    """Chart 5: Histogram of BGP prefix lengths (/16, /22, /24, etc.)."""
    lengths = df["PrefixLength"].dropna()
    if lengths.empty:
        return ""

    fig, ax = plt.subplots(figsize=(8, 5))
    counts = lengths.astype(int).value_counts().sort_index()
    ax.bar(
        counts.index.astype(str),
        counts.values,
        color="#3498db",
        edgecolor="white",
    )
    for i, (idx, val) in enumerate(counts.items()):
        ax.text(i, val + 0.1, str(val), ha="center", fontsize=10, fontweight="bold")

    apply_style(fig, ax, title="Prefix Length Distribution",
                xlabel="Prefix Length", ylabel="Count")
    ax.set_xticks(range(len(counts)))
    ax.set_xticklabels([f"/{v}" for v in counts.index], rotation=0)
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


def chart_maxlength_gap(df: pd.DataFrame, out: str) -> str:
    """Chart 6: Bar chart of MaxLength gap for Case 2 (RPKI-valid, MaxLen > Prefix)."""
    case2 = df[df["Erosion Case?"] == 2].copy()
    case2 = case2.dropna(subset=["Gap"])
    if case2.empty:
        return ""

    # Label: Company (IP)
    case2["Label"] = case2["Company Name"].fillna("") + " (" + case2["IP Addresses"].fillna("") + ")"

    fig, ax = plt.subplots(figsize=(10, max(4, len(case2) * 0.5)))
    ax.barh(case2["Label"], case2["Gap"], color="#f39c12", edgecolor="white")
    for i, (_, row) in enumerate(case2.iterrows()):
        ax.text(row["Gap"] + 0.1, i, f"/{int(row['PrefixLength'])} → /{int(row['MaxLengthNum'])}",
                va="center", fontsize=9)

    apply_style(fig, ax, title="MaxLength Gap — Case 2 (Forged-Origin Sub-Prefix Hijack Exposure)",
                xlabel="Gap (MaxLength − Prefix Length)")
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out

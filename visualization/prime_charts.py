"""Charts derived from Prime Intellect pod data (prime_pod_results.csv)."""

import numpy as np
import matplotlib.pyplot as plt
import pandas as pd

from visualization.style import apply_style


def chart_gpu_pricing(df: pd.DataFrame, out: str) -> str:
    """Chart 7: Grouped bar — GPU type × price/hr, grouped by provider."""
    subset = df[["GPU Type", "Provider Type", "Price per Hour"]].dropna()
    if subset.empty:
        return ""

    pivot = subset.pivot_table(
        index="GPU Type", columns="Provider Type",
        values="Price per Hour", aggfunc="mean",
    )

    fig, ax = plt.subplots(figsize=(max(8, len(pivot) * 1.5), 6))
    x = np.arange(len(pivot.index))
    width = 0.8 / max(len(pivot.columns), 1)

    for i, provider in enumerate(pivot.columns):
        vals = pivot[provider].values
        offset = (i - len(pivot.columns) / 2 + 0.5) * width
        bars = ax.bar(x + offset, vals, width, label=provider, edgecolor="white")
        for bar, val in zip(bars, vals):
            if not np.isnan(val):
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.02,
                        f"${val:.2f}", ha="center", va="bottom", fontsize=8)

    ax.set_xticks(x)
    ax.set_xticklabels(pivot.index, rotation=45, ha="right")
    ax.legend(fontsize=9)
    apply_style(fig, ax, title="GPU Provider Pricing ($/hr)", ylabel="Price per Hour ($)")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


def chart_provider_geography(df: pd.DataFrame, out: str) -> str:
    """Chart 8: Stacked bar — Provider × count per country."""
    if "AvailCountry" not in df.columns:
        return ""

    subset = df[["Provider Type", "AvailCountry"]].dropna()
    subset = subset[subset["AvailCountry"] != ""]
    if subset.empty:
        return ""

    pivot = subset.groupby(["Provider Type", "AvailCountry"]).size().unstack(fill_value=0)

    fig, ax = plt.subplots(figsize=(max(8, len(pivot) * 1.2), 6))
    bottom = np.zeros(len(pivot))
    colors = plt.cm.Set2(np.linspace(0, 1, len(pivot.columns)))

    for i, country in enumerate(pivot.columns):
        vals = pivot[country].values
        ax.bar(pivot.index, vals, bottom=bottom, label=country,
               color=colors[i], edgecolor="white")
        bottom += vals

    ax.legend(title="Country", fontsize=9)
    apply_style(fig, ax, title="Provider Geographic Distribution", ylabel="Pod Count")
    ax.set_xticks(range(len(pivot.index)))
    ax.set_xticklabels(pivot.index, rotation=45, ha="right")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out

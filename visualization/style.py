"""Shared visual theme for all charts."""

import matplotlib.pyplot as plt

# ── Erosion case palette ─────────────────────────────────────────────────────

CASE_COLORS = {
    1: "#2ecc71",
    2: "#f39c12",
    3: "#e67e22",
    4: "#e74c3c",
}

CASE_LABELS = {
    1: "Case 1 — ROA exists, MaxLen = prefix",
    2: "Case 2 — ROA exists, MaxLen > prefix",
    3: "Case 3 — No ROA, prefix = /24",
    4: "Case 4 — No ROA, prefix > /24",
}

CASE_LABELS_SHORT = {
    1: "Case 1",
    2: "Case 2",
    3: "Case 3",
    4: "Case 4",
}

# ── Theme helper ─────────────────────────────────────────────────────────────


def apply_style(fig, ax, title: str = "", xlabel: str = "", ylabel: str = ""):
    """Apply a consistent publication-quality style to a figure."""
    if title:
        ax.set_title(title, fontsize=14, fontweight="bold", pad=12)
    if xlabel:
        ax.set_xlabel(xlabel, fontsize=11)
    if ylabel:
        ax.set_ylabel(ylabel, fontsize=11)

    ax.tick_params(labelsize=10)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.set_axisbelow(True)
    fig.tight_layout()

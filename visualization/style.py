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
    1: "Case 1 — RPKI-enabled, MaxLen = Prefix (/24)",
    2: "Case 2 — RPKI-enabled, MaxLen > Prefix",
    3: "Case 3 — No ROA, Prefix = /24",
    4: "Case 4 — No ROA, Prefix shorter than /24",
}

# Short labels for tight spaces (bar annotations, legends)
CASE_LABELS_SHORT = {
    1: "Case 1 (RPKI-enabled, /24)",
    2: "Case 2 (RPKI-enabled, MaxLen gap)",
    3: "Case 3 (No ROA, /24)",
    4: "Case 4 (No ROA, shorter prefix)",
}

# Backwards compat aliases
EROSION_COLORS = CASE_COLORS
EROSION_LABELS = CASE_LABELS_SHORT

ROA_COLORS = {"Valid": "#2ecc71", "Not Valid": "#e74c3c"}


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

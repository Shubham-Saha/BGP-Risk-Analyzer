"""Research-grade charts for the BGP security paper.

These charts focus on cross-referenced findings that demonstrate
the systemic vulnerability of decentralized AI training infrastructure.
"""

import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
from matplotlib.patches import Patch
import pandas as pd

from visualization.style import CASE_COLORS, CASE_LABELS, CASE_LABELS_SHORT, apply_style


# ── Chart 12: Attack Surface Concentration Curve ────────────────────────────


def chart_attack_surface(df: pd.DataFrame, out: str) -> str:
    """Chart 12: Infrastructure concentration at the BGP layer.

    Shows how few BGP prefixes cover the majority of observed training IPs,
    illustrating the concentration risk in the underlying routing infrastructure.
    """
    import matplotlib
    original_family = matplotlib.rcParams["font.family"]
    original_serif = list(matplotlib.rcParams["font.serif"])
    matplotlib.rcParams["font.family"] = "serif"
    matplotlib.rcParams["font.serif"] = ["Times New Roman"] + original_serif

    required = ["Pod IP", "Prefix", "Erosion Case?"]
    if not all(c in df.columns for c in required):
        matplotlib.rcParams["font.family"] = original_family
        matplotlib.rcParams["font.serif"] = original_serif
        return ""

    subset = df[df["Pod IP"].notna() & (df["Pod IP"] != "")].copy()
    subset = subset.dropna(subset=["Prefix", "Erosion Case?"])
    if subset.empty:
        matplotlib.rcParams["font.family"] = original_family
        matplotlib.rcParams["font.serif"] = original_serif
        return ""

    # Deduplicate: count unique IPs per prefix, track case
    ip_prefix = subset.drop_duplicates(subset=["Pod IP"])[
        ["Pod IP", "Prefix", "Erosion Case?"]
    ]
    ip_prefix["Erosion Case?"] = ip_prefix["Erosion Case?"].astype(int)
    prefix_counts = ip_prefix.groupby("Prefix").size().sort_values(ascending=False)
    total_ips = len(ip_prefix)

    if total_ips == 0:
        matplotlib.rcParams["font.family"] = original_family
        matplotlib.rcParams["font.serif"] = original_serif
        return ""

    # Build cumulative curve
    cum_ips = prefix_counts.cumsum()
    cum_pct = (cum_ips / total_ips * 100).values
    x = np.arange(1, len(cum_pct) + 1)

    fig, ax = plt.subplots(figsize=(10, 6))

    # Fill area under curve
    ax.fill_between(x, cum_pct, alpha=0.15, color="#e74c3c")
    ax.plot(x, cum_pct, "o-", color="#e74c3c", linewidth=2, markersize=4)

    # Mark key thresholds: 25%, 50%, 75%, 90%
    thresholds = [25, 50, 75, 90]
    for pct in thresholds:
        idx = np.searchsorted(cum_pct, pct)
        if idx < len(cum_pct):
            actual_pct = cum_pct[idx]
            n_prefixes = idx + 1
            ax.axhline(y=pct, color="#bbb", linestyle=":", alpha=0.6)
            ax.plot(n_prefixes, actual_pct, "D", color="#c0392b", markersize=10,
                    zorder=5)
            ax.annotate(
                f"{n_prefixes} prefixes \u2192 {actual_pct:.0f}%",
                xy=(n_prefixes, actual_pct),
                xytext=(n_prefixes + 1.5, actual_pct - 3),
                fontsize=10, fontweight="bold", color="#c0392b",
                arrowprops=dict(arrowstyle="->", color="#c0392b", lw=1.2),
            )

    # Case breakdown across ALL prefixes
    n_prot_ips = len(ip_prefix[ip_prefix["Erosion Case?"] == 1])
    n_vuln_ips = len(ip_prefix[ip_prefix["Erosion Case?"] > 1])
    pfx_case_max = ip_prefix.groupby("Prefix")["Erosion Case?"].max()
    n_prot_pfx = int((pfx_case_max == 1).sum())
    n_vuln_pfx = int((pfx_case_max > 1).sum())

    ax.text(
        0.98, 0.28,
        f"All {len(prefix_counts)} prefixes:\n"
        f"  {n_prot_pfx} prefixes ({n_prot_ips} IPs) \u2014 Case 1\n"
        f"  {n_vuln_pfx} prefixes ({n_vuln_ips} IPs) \u2014 Cases 2\u20134",
        transform=ax.transAxes, ha="right", fontsize=9,
        color="#333", family="monospace",
        bbox=dict(boxstyle="round,pad=0.4", facecolor="#f9f9f9",
                  edgecolor="#ccc", alpha=0.9),
    )

    ax.set_xlim(0, len(cum_pct) + 1)
    ax.set_ylim(0, 105)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter())

    # Add secondary info: total counts
    ax.text(0.98, 0.05,
            f"Total: {total_ips} unique IPs across {len(prefix_counts)} prefixes",
            transform=ax.transAxes, ha="right", fontsize=10, color="#666",
            style="italic")

    apply_style(fig, ax,
                title="Infrastructure Concentration at the BGP Layer",
                xlabel="Number of BGP Prefixes (ranked by IP density)",
                ylabel="Cumulative % of Observed Training IPs Covered")

    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)

    matplotlib.rcParams["font.family"] = original_family
    matplotlib.rcParams["font.serif"] = original_serif
    return out


# ── Chart 13: Provider Security Posture Comparison ──────────────────────────


def chart_provider_security(df: pd.DataFrame, out: str) -> str:
    """Chart 13: Provider security posture — ROA validity + erosion case breakdown.

    Side-by-side view showing which providers have RPKI protection and which don't.
    """
    required = ["Provider Type", "ROA Return", "Erosion Case?"]
    if not all(c in df.columns for c in required):
        return ""

    subset = df.dropna(subset=required).copy()
    subset = subset[subset["Provider Type"].str.strip() != ""]
    if subset.empty:
        return ""

    providers = subset["Provider Type"].unique()
    if len(providers) < 2:
        return ""

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # ─── Left panel: % susceptible (Case 2/3/4) per provider ───
    vuln_data = []
    for prov in sorted(providers):
        prov_df = subset[subset["Provider Type"] == prov]
        total = len(prov_df)
        safe = len(prov_df[prov_df["Erosion Case?"] == 1])
        vuln_pct = (total - safe) / total * 100
        vuln_data.append({"Provider": prov, "Vulnerable %": vuln_pct,
                          "Safe %": 100 - vuln_pct, "Total": total})

    vuln_df = pd.DataFrame(vuln_data).sort_values("Vulnerable %", ascending=True)

    colors_vuln = ["#e74c3c" if v > 50 else "#f39c12" if v > 20 else "#2ecc71"
                   for v in vuln_df["Vulnerable %"]]

    bars = ax1.barh(vuln_df["Provider"], vuln_df["Vulnerable %"],
                    color=colors_vuln, edgecolor="white", height=0.6)

    for bar, row in zip(bars, vuln_df.itertuples()):
        pct = row._2  # Vulnerable %
        total = row.Total
        ax1.text(max(pct + 1, 5), bar.get_y() + bar.get_height() / 2,
                 f"{pct:.0f}% Cases 2–4 ({total} pods)",
                 va="center", fontsize=10, fontweight="bold")

    ax1.set_xlim(0, 110)
    ax1.axvline(x=50, color="#e74c3c", linestyle="--", alpha=0.4)
    apply_style(fig, ax1, title="BGP Hijack Classification by Provider",
                xlabel="% of Pods in Cases 2–4 (easier to exploit)")

    # ─── Right panel: Erosion case stacked bar per provider ───
    pivot = subset.groupby(["Provider Type", "Erosion Case?"]).size().unstack(fill_value=0)
    # Normalize to percentage
    pivot_pct = pivot.div(pivot.sum(axis=1), axis=0) * 100
    pivot_pct = pivot_pct.loc[vuln_df["Provider"].values]  # same order

    left = np.zeros(len(pivot_pct))
    for case in sorted(pivot_pct.columns):
        vals = pivot_pct[case].values
        ax2.barh(
            pivot_pct.index, vals, left=left,
            label=CASE_LABELS_SHORT.get(int(case), f"Case {int(case)}"),
            color=CASE_COLORS.get(int(case), "#999"),
            edgecolor="white", height=0.6,
        )
        left += vals

    ax2.set_xlim(0, 105)
    ax2.xaxis.set_major_formatter(mticker.PercentFormatter())
    ax2.legend(fontsize=8, loc="lower right")
    apply_style(fig, ax2, title="BGP Hijacking Case Distribution by Provider",
                xlabel="Percentage of Pods")

    fig.suptitle("Provider Security Posture Comparison",
                 fontsize=15, fontweight="bold", y=1.02)
    fig.tight_layout()
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


# ── Chart 14: GPU Type vs Vulnerability ─────────────────────────────────────


def chart_gpu_vulnerability(df: pd.DataFrame, out: str) -> str:
    """Chart 14: GPU type vulnerability — which hardware is most at risk.

    Highlights that the most commonly used GPUs (A100, RTX5090) are the
    least protected, creating maximum impact if hijacked.
    """
    required = ["GPU Type", "Erosion Case?"]
    if not all(c in df.columns for c in required):
        return ""

    subset = df.dropna(subset=required).copy()
    subset = subset[subset["GPU Type"].str.strip() != ""]
    if subset.empty:
        return ""

    # Per GPU: total pods, % susceptible
    gpu_stats = []
    for gpu in subset["GPU Type"].unique():
        g = subset[subset["GPU Type"] == gpu]
        total = len(g)
        safe = len(g[g["Erosion Case?"] == 1])
        vuln = total - safe
        gpu_stats.append({
            "GPU": gpu, "Total": total,
            "Safe": safe, "Vulnerable": vuln,
            "Vuln%": vuln / total * 100,
        })

    gpu_df = pd.DataFrame(gpu_stats).sort_values("Vuln%", ascending=True)

    fig, ax = plt.subplots(figsize=(12, max(5, len(gpu_df) * 0.55)))

    # Stacked bars: Case 1 (green) + Cases 2-4 (red)
    bars_safe = ax.barh(gpu_df["GPU"], gpu_df["Safe"],
                        color="#2ecc71", edgecolor="white", height=0.65,
                        label="Case 1 (hardest to exploit)")
    bars_vuln = ax.barh(gpu_df["GPU"], gpu_df["Vulnerable"],
                        left=gpu_df["Safe"],
                        color="#e74c3c", edgecolor="white", height=0.65,
                        label="Cases 2–4 (easier to exploit)")

    # Annotate with percentage
    for i, row in gpu_df.iterrows():
        total = row["Total"]
        vuln_pct = row["Vuln%"]
        x_pos = total + 0.3
        label = f"{vuln_pct:.0f}% Cases 2–4 ({int(total)} pods)"
        color = "#e74c3c" if vuln_pct > 50 else "#f39c12" if vuln_pct > 0 else "#2ecc71"
        ax.text(x_pos, row["GPU"], label, va="center", fontsize=9,
                fontweight="bold", color=color)

    ax.legend(fontsize=10, loc="lower right")
    apply_style(fig, ax,
                title="BGP Hijacking Classification by GPU Type",
                xlabel="Number of Pods")

    fig.tight_layout()
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


# ── Chart 15: Geographic Risk Map ───────────────────────────────────────────


def chart_geographic_risk(df: pd.DataFrame, out: str) -> str:
    """Chart 15: Geographic vulnerability — country-level security posture.

    Shows which hosting countries have RPKI protection and which don't,
    with bubble size representing infrastructure volume.
    """
    if "Country" not in df.columns:
        return ""

    subset = df.dropna(subset=["Country", "Erosion Case?"]).copy()
    subset = subset[subset["Country"].str.strip() != ""]
    if subset.empty:
        return ""

    # Per country stats
    country_stats = []
    for country in subset["Country"].unique():
        c = subset[subset["Country"] == country]
        total = len(c)
        case_counts = c["Erosion Case?"].astype(int).value_counts()
        safe = case_counts.get(1, 0)
        vuln = total - safe
        country_stats.append({
            "Country": country, "Total": total,
            "Safe": safe, "Vulnerable": vuln,
            "Vuln%": vuln / total * 100,
            "Case1": case_counts.get(1, 0),
            "Case2": case_counts.get(2, 0),
            "Case3": case_counts.get(3, 0),
            "Case4": case_counts.get(4, 0),
        })

    cdf = pd.DataFrame(country_stats).sort_values("Vuln%", ascending=True)

    fig, ax = plt.subplots(figsize=(12, max(5, len(cdf) * 0.7)))

    # Stacked horizontal bars for each erosion case
    left = np.zeros(len(cdf))
    for case in [1, 2, 3, 4]:
        col = f"Case{case}"
        vals = cdf[col].values
        ax.barh(cdf["Country"], vals, left=left, height=0.6,
                color=CASE_COLORS[case], edgecolor="white",
                label=CASE_LABELS_SHORT[case])
        left += vals

    # Annotate with % in Cases 2–4
    for _, row in cdf.iterrows():
        vuln_pct = row["Vuln%"]
        total = row["Total"]
        x_pos = total + 0.3
        if vuln_pct == 0:
            label = f"0% Cases 2–4 ({int(total)} pods)"
            color = "#2ecc71"
        elif vuln_pct == 100:
            label = f"100% Cases 2–4 ({int(total)} pods)"
            color = "#e74c3c"
        else:
            label = f"{vuln_pct:.0f}% Cases 2–4 ({int(total)} pods)"
            color = "#e67e22"
        ax.text(x_pos, row["Country"], label, va="center", fontsize=9,
                fontweight="bold", color=color)

    ax.legend(fontsize=9, loc="lower right")
    apply_style(fig, ax,
                title="Geographic Distribution of BGP Hijack Susceptibility",
                xlabel="Number of Pods")

    fig.tight_layout()
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


# ── Chart 16: Case 2 Deep Dive — False Sense of Security ───────────────────


def chart_case2_deep_dive(df: pd.DataFrame, out: str) -> str:
    """Chart 16: Case 2 deep dive — ROAs that provide a false sense of security.

    Shows the MaxLength gap that allows forged-origin sub-prefix hijacks
    even when RPKI appears to be in place, grouped by provider.
    """
    required = ["Erosion Case?", "Prefix", "Provider Type"]
    if not all(c in df.columns for c in required):
        return ""

    # Get Case 2 entries
    case2 = df[df["Erosion Case?"] == 2].copy()
    if case2.empty or len(case2) < 2:
        return ""

    # Need PrefixLength and MaxLengthNum
    if "PrefixLength" not in case2.columns:
        case2["PrefixLength"] = (
            case2["Prefix"].astype(str).str.extract(r"/(\d+)$")[0].astype(float)
        )
    if "MaxLengthNum" not in case2.columns:
        case2["MaxLengthNum"] = (
            case2["MaxLength"].astype(str).str.extract(r"/?(\d+)")[0].astype(float)
        )
    if "Gap" not in case2.columns:
        case2["Gap"] = case2["MaxLengthNum"] - case2["PrefixLength"]

    case2 = case2.dropna(subset=["Gap", "PrefixLength", "MaxLengthNum"])
    if case2.empty:
        return ""

    # Deduplicate: same prefix + provider → one entry
    dedup = case2.drop_duplicates(subset=["Prefix", "Provider Type"])

    # Build label
    dedup = dedup.copy()
    company_col = "Company Name" if "Company Name" in dedup.columns else "Provider Type"
    dedup["Label"] = (
        dedup[company_col].fillna("") + "\n"
        + dedup["Prefix"].fillna("") + " → /"
        + dedup["MaxLengthNum"].astype(int).astype(str)
    )

    dedup = dedup.sort_values("Gap", ascending=True)

    fig, ax = plt.subplots(figsize=(12, max(5, len(dedup) * 0.65)))

    # Color by gap severity
    gap_colors = []
    for g in dedup["Gap"]:
        if g >= 8:
            gap_colors.append("#e74c3c")    # extreme
        elif g >= 4:
            gap_colors.append("#e67e22")    # high
        elif g >= 2:
            gap_colors.append("#f39c12")    # medium
        else:
            gap_colors.append("#f1c40f")    # low

    bars = ax.barh(dedup["Label"], dedup["Gap"], color=gap_colors,
                   edgecolor="white", height=0.6)

    # Annotate with gap details
    for bar, (_, row) in zip(bars, dedup.iterrows()):
        gap = row["Gap"]
        plen = int(row["PrefixLength"])
        mlen = int(row["MaxLengthNum"])
        # Number of possible sub-prefix hijack routes
        n_subprefixes = sum(2 ** (l - plen) for l in range(plen + 1, mlen + 1))
        ax.text(bar.get_width() + 0.15, bar.get_y() + bar.get_height() / 2,
                f"Gap: {int(gap)} levels\n({n_subprefixes} possible sub-prefixes)",
                va="center", fontsize=9, fontweight="bold", color="#c0392b")

    # Legend for severity
    legend_handles = [
        Patch(facecolor="#f1c40f", label="Low (gap 1)"),
        Patch(facecolor="#f39c12", label="Medium (gap 2-3)"),
        Patch(facecolor="#e67e22", label="High (gap 4-7)"),
        Patch(facecolor="#e74c3c", label="Extreme (gap 8+)"),
    ]
    ax.legend(handles=legend_handles, fontsize=9, loc="lower right",
              title="Gap Severity")

    apply_style(fig, ax,
                title="Case 2 — False Sense of Security:\nROAs with MaxLength Gaps Enabling Forged-Origin Sub-Prefix Hijacks",
                xlabel="MaxLength Gap (levels)")
    ax.set_ylabel("")

    fig.tight_layout()
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


# ── Chart 17: Cross-Provider Prefix Sharing (Blast Radius) ─────────────────


def chart_shared_prefixes(df: pd.DataFrame, out: str) -> str:
    """Chart 17: Shared prefixes — a single BGP hijack affects multiple providers.

    Shows prefixes that are used by more than one provider, demonstrating
    that the blast radius of a hijack extends across provider boundaries.
    Also shows single-provider prefixes with high IP counts as high-value targets.
    """
    required = ["Pod IP", "Prefix", "Provider Type"]
    if not all(c in df.columns for c in required):
        return ""

    subset = df.dropna(subset=required).copy()
    subset = subset[subset["Pod IP"].str.strip() != ""]
    if subset.empty:
        return ""

    # Per prefix: unique providers, unique IPs, erosion case breakdown
    prefix_data = []
    for prefix, grp in subset.groupby("Prefix"):
        ips = grp["Pod IP"].nunique()
        providers = sorted(grp["Provider Type"].dropna().unique())
        n_providers = len(providers)
        cases = grp["Erosion Case?"].dropna().astype(int).value_counts().to_dict()
        prefix_data.append({
            "Prefix": prefix,
            "IPs": ips,
            "Providers": n_providers,
            "ProviderList": ", ".join(providers),
            "ErosionCase": grp["Erosion Case?"].dropna().astype(int).mode().iloc[0]
                          if not grp["Erosion Case?"].dropna().empty else 0,
            **{f"Case{c}": cases.get(c, 0) for c in [1, 2, 3, 4]},
        })

    pdf = pd.DataFrame(prefix_data)

    # Show: (1) multi-provider prefixes, (2) top single-provider prefixes by IP count
    multi = pdf[pdf["Providers"] > 1].copy()
    top_single = pdf[pdf["Providers"] == 1].sort_values("IPs", ascending=False).head(8)
    combined = pd.concat([multi, top_single]).sort_values("IPs", ascending=True)

    if combined.empty:
        return ""

    fig, ax = plt.subplots(figsize=(12, max(5, len(combined) * 0.6)))

    # Color: multi-provider = red, single = blue
    colors = ["#e74c3c" if p > 1 else "#3498db" for p in combined["Providers"]]
    edge_colors = ["#c0392b" if p > 1 else "#2980b9" for p in combined["Providers"]]

    # Label: prefix + providers
    labels = []
    for _, row in combined.iterrows():
        if row["Providers"] > 1:
            labels.append(f"{row['Prefix']}\n({row['ProviderList']})")
        else:
            labels.append(f"{row['Prefix']}\n({row['ProviderList']})")

    bars = ax.barh(labels, combined["IPs"], color=colors, edgecolor=edge_colors,
                   height=0.65, linewidth=1.5)

    # Annotate with erosion case info
    for bar, (_, row) in zip(bars, combined.iterrows()):
        case_str = ""
        for c in [1, 2, 3, 4]:
            n = row.get(f"Case{c}", 0)
            if n > 0:
                case_str += f"C{c}:{n} "
        ax.text(bar.get_width() + 0.15, bar.get_y() + bar.get_height() / 2,
                f"{int(row['IPs'])} IPs — {case_str.strip()}",
                va="center", fontsize=9, fontweight="bold")

    # Legend
    legend_handles = [
        Patch(facecolor="#e74c3c", edgecolor="#c0392b", linewidth=1.5,
              label="Multi-provider prefix (cross-boundary risk)"),
        Patch(facecolor="#3498db", edgecolor="#2980b9", linewidth=1.5,
              label="Single-provider prefix (high-value target)"),
    ]
    ax.legend(handles=legend_handles, fontsize=9, loc="lower right")

    apply_style(fig, ax,
                title="Potential BGP Hijack Blast Radius: IPs per Prefix\nShared Prefixes Create Cross-Provider Exposure",
                xlabel="Number of Unique AI Training IPs")
    ax.set_ylabel("")

    fig.tight_layout()
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


# ── Chart 18: Provider Security Posture — Unique IPs ─────────────────────────


def chart_provider_security_by_ip(df: pd.DataFrame, out: str) -> str:
    """Chart 18: Provider security posture deduplicated by unique IP.

    Same analysis as Chart 13 but counts each IP address once, since
    BGP hijacking classification is per-IP, not per-pod.
    """
    required = ["Pod IP", "Provider Type", "ROA Return", "Erosion Case?"]
    if not all(c in df.columns for c in required):
        return ""

    # Deduplicate: one row per unique IP
    subset = df.drop_duplicates(subset=["Pod IP"]).dropna(subset=required).copy()
    subset = subset[subset["Provider Type"].str.strip() != ""]
    if subset.empty:
        return ""

    providers = subset["Provider Type"].unique()
    if len(providers) < 2:
        return ""

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # ─── Left panel: % Cases 2-4 per provider ───
    vuln_data = []
    for prov in sorted(providers):
        prov_df = subset[subset["Provider Type"] == prov]
        total = len(prov_df)
        case1 = len(prov_df[prov_df["Erosion Case?"] == 1])
        c234 = total - case1
        vuln_pct = c234 / total * 100
        vuln_data.append({"Provider": prov, "Vulnerable %": vuln_pct,
                          "Safe %": 100 - vuln_pct, "Total": total})

    vuln_df = pd.DataFrame(vuln_data).sort_values("Vulnerable %", ascending=True)

    colors_vuln = ["#e74c3c" if v > 50 else "#f39c12" if v > 20 else "#2ecc71"
                   for v in vuln_df["Vulnerable %"]]

    bars = ax1.barh(vuln_df["Provider"], vuln_df["Vulnerable %"],
                    color=colors_vuln, edgecolor="white", height=0.6)

    for bar, row in zip(bars, vuln_df.itertuples()):
        pct = row._2  # Vulnerable %
        total = row.Total
        ax1.text(max(pct + 1, 5), bar.get_y() + bar.get_height() / 2,
                 f"{pct:.0f}% Cases 2–4 ({total} IPs)",
                 va="center", fontsize=10, fontweight="bold")

    ax1.set_xlim(0, 110)
    ax1.axvline(x=50, color="#e74c3c", linestyle="--", alpha=0.4)
    apply_style(fig, ax1, title="BGP Hijack Classification by Provider",
                xlabel="% of Unique IPs in Cases 2–4 (easier to exploit)")

    # ─── Right panel: Erosion case stacked bar per provider ───
    pivot = subset.groupby(["Provider Type", "Erosion Case?"]).size().unstack(fill_value=0)
    pivot_pct = pivot.div(pivot.sum(axis=1), axis=0) * 100
    pivot_pct = pivot_pct.loc[vuln_df["Provider"].values]  # same order

    left = np.zeros(len(pivot_pct))
    for case in sorted(pivot_pct.columns):
        vals = pivot_pct[case].values
        ax2.barh(
            pivot_pct.index, vals, left=left,
            label=CASE_LABELS_SHORT.get(int(case), f"Case {int(case)}"),
            color=CASE_COLORS.get(int(case), "#999"),
            edgecolor="white", height=0.6,
        )
        left += vals

    ax2.set_xlim(0, 105)
    ax2.xaxis.set_major_formatter(mticker.PercentFormatter())
    ax2.legend(fontsize=8, loc="lower right")
    apply_style(fig, ax2, title="BGP Hijacking Case Distribution by Provider",
                xlabel="Percentage of Unique IPs")

    fig.suptitle("Provider Security Posture — Unique IPs",
                 fontsize=15, fontweight="bold", y=1.02)
    fig.tight_layout()
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


# ── Chart 19: Provider Breakdown ─────────────────────────────────────────────


def chart_enumeration_funnel(df: pd.DataFrame, out: str) -> str:
    """Chart 19: Per-provider reconnaissance breakdown.

    Shows offerings → unique IPs → BGP prefixes for each provider,
    giving a high-level overview of where the infrastructure lives.
    """
    from visualization.loader import load_bgp_data, load_prime_data

    prime = load_prime_data()
    bgp = load_bgp_data()

    if prime.empty:
        return ""

    # --- Compute per-provider stats ---
    has_ip = prime["Pod IP"].notna() & (prime["Pod IP"].astype(str).str.strip().str.len() > 0)

    providers = sorted(prime["Provider Type"].dropna().unique())
    rows = []
    for prov in providers:
        subset = prime[prime["Provider Type"] == prov]
        n_offerings = len(subset)
        ip_subset = subset.loc[has_ip]
        n_unique_ips = int(ip_subset["Pod IP"].nunique())

        ips = ip_subset["Pod IP"].dropna().unique()
        if not bgp.empty:
            matched = bgp[bgp["IP Addresses"].isin(ips)]
            n_prefixes = int(matched["Prefix"].nunique())
            n_asns = int(matched["ASN"].nunique())
        else:
            n_prefixes = n_asns = 0

        rows.append({
            "provider": prov,
            "offerings": n_offerings,
            "unique_ips": n_unique_ips,
            "prefixes": n_prefixes,
            "asns": n_asns,
        })

    # Sort by offerings descending (dominant provider on top)
    rows.sort(key=lambda r: r["offerings"], reverse=True)

    # Totals (use actual unique counts, not sums — prefixes may be shared)
    total_offerings = sum(r["offerings"] for r in rows)
    all_ips_series = prime.loc[has_ip, "Pod IP"]
    total_ips = int(all_ips_series.nunique())
    if not bgp.empty:
        total_prefixes = int(bgp["Prefix"].nunique())
        total_asns = int(bgp["ASN"].nunique())
    else:
        total_prefixes = total_asns = 0

    # --- Pretty provider names ---
    _PROV_NAMES = {
        "runpod": "RunPod",
        "datacrunch": "Verda (DataCrunch)",
        "crusoecloud": "Crusoe Cloud",
        "massedcompute": "Massed Compute",
        "lambdalabs": "Lambda Labs",
        "nebius": "Nebius",
        "dc_wildebeest": "DC Wildebeest",
        "dc_gnu": "DC Gnu",
    }

    # --- Draw chart ---
    old_rc = matplotlib.rcParams.copy()
    matplotlib.rcParams["font.family"] = "serif"
    matplotlib.rcParams["font.serif"] = ["Times New Roman"]

    try:
        n_prov = len(rows)
        fig, ax = plt.subplots(figsize=(10, 4.5))

        bar_height = 0.22
        y_positions = np.arange(n_prov)  # providers only, no total row
        metrics = ["offerings", "unique_ips", "prefixes"]
        labels = ["GPU Offerings", "Unique IPs", "BGP Prefixes"]
        colors = ["#85C1E9", "#2E86C1", "#1B4F72"]

        # Determine max value for x-axis
        max_val = max(r["offerings"] for r in rows)

        for j, (metric, label, color) in enumerate(zip(metrics, labels, colors)):
            values = [r[metric] for r in rows]
            y_pos = y_positions - (1 - j) * bar_height

            bars = ax.barh(y_pos, values, height=bar_height, color=color,
                           label=label, edgecolor="white", linewidth=0.5)

            for bar, val in zip(bars, values):
                if val > 0:
                    ax.text(bar.get_width() + max_val * 0.01,
                            bar.get_y() + bar.get_height() / 2,
                            str(val), va="center", ha="left",
                            fontsize=8, fontweight="bold", color=color)

        # Provider labels on y-axis
        prov_labels = [_PROV_NAMES.get(r["provider"], r["provider"]) for r in rows]
        ax.set_yticks(y_positions)
        ax.set_yticklabels(prov_labels, fontsize=11)

        # Invert y so largest provider is on top
        ax.invert_yaxis()

        # Clean up axes
        ax.set_xlabel("")
        ax.set_xlim(0, max_val * 1.1)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["bottom"].set_visible(False)
        ax.tick_params(bottom=False, labelbottom=False)
        ax.grid(axis="x", linestyle="--", alpha=0.3)

        # Legend in the bottom-right (dead space below the long bars)
        ax.legend(loc="lower right", fontsize=10, framealpha=0.9,
                  ncol=1, borderpad=0.5)

        # Title
        ax.set_title("Reconnaissance: Provider Breakdown",
                      fontsize=14, fontweight="bold", pad=15, color="#1B4F72")

        # Subtitle with totals
        ax.text(0.5, 1.02,
                f"{total_offerings} offerings  |  {n_prov} providers  |  "
                f"{total_ips} unique IPs  |  "
                f"{total_prefixes} prefixes  |  {total_asns} ASNs",
                transform=ax.transAxes, ha="center", fontsize=10,
                color="#555", style="italic")

        fig.tight_layout()
        fig.savefig(out, dpi=150, bbox_inches="tight")
        plt.close(fig)

    finally:
        matplotlib.rcParams.update(old_rc)

    return out


# ── Chart 20: Provider Vulnerability Breakdown ───────────────────────────────


def chart_provider_vulnerability(df: pd.DataFrame, out: str) -> str:
    """Chart 20: Stacked bar — case distribution per provider.

    Shows which providers have the most IPs in higher-risk cases.
    """
    from visualization.loader import load_prime_data

    prime = load_prime_data()
    if prime.empty or "Erosion Case?" not in df.columns:
        return ""

    # Map IP -> provider
    has_ip = prime["Pod IP"].notna() & (prime["Pod IP"].astype(str).str.strip().str.len() > 0)
    ip_prov = {}
    for _, row in prime[has_ip].iterrows():
        ip_prov[str(row["Pod IP"]).strip()] = str(row["Provider Type"]).strip()

    df = df.copy()
    df["Provider"] = df["Pod IP"].map(ip_prov)
    df = df.dropna(subset=["Provider", "Erosion Case?"])
    df["Erosion Case?"] = df["Erosion Case?"].astype(int)

    if df.empty:
        return ""

    _PROV_NAMES = {
        "runpod": "RunPod",
        "datacrunch": "Verda (DataCrunch)",
        "crusoecloud": "Crusoe Cloud",
        "massedcompute": "Massed Compute",
        "lambdalabs": "Lambda Labs",
        "nebius": "Nebius",
        "dc_wildebeest": "DC Wildebeest",
        "dc_gnu": "DC Gnu",
    }

    # Compute per-provider case counts, sorted by total IPs descending
    providers = df.groupby("Provider")["Pod IP"].nunique().sort_values(ascending=False).index
    case_nums = [1, 2, 3, 4]

    prov_labels = []
    case_counts = {c: [] for c in case_nums}
    for prov in providers:
        subset = df[df["Provider"] == prov].drop_duplicates(subset=["Pod IP"])
        prov_labels.append(_PROV_NAMES.get(prov, prov))
        counts = subset["Erosion Case?"].value_counts()
        for c in case_nums:
            case_counts[c].append(counts.get(c, 0))

    old_rc = matplotlib.rcParams.copy()
    matplotlib.rcParams["font.family"] = "serif"
    matplotlib.rcParams["font.serif"] = ["Times New Roman"]

    try:
        fig, ax = plt.subplots(figsize=(10, 5))

        y = np.arange(len(prov_labels))
        bar_height = 0.6
        left = np.zeros(len(prov_labels))

        for c in case_nums:
            values = np.array(case_counts[c])
            bars = ax.barh(y, values, height=bar_height, left=left,
                           color=CASE_COLORS[c], label=CASE_LABELS_SHORT[c],
                           edgecolor="white", linewidth=0.5)
            # Label segments that are wide enough
            for bar, val in zip(bars, values):
                if val > 0:
                    cx = bar.get_x() + bar.get_width() / 2
                    cy = bar.get_y() + bar.get_height() / 2
                    ax.text(cx, cy, str(val), ha="center", va="center",
                            fontsize=9, fontweight="bold", color="white")
            left += values

        # Total count at end of each bar
        totals = left.astype(int)
        for i, total in enumerate(totals):
            ax.text(total + 0.5, i, str(total), va="center", ha="left",
                    fontsize=10, fontweight="bold", color="#333")

        ax.set_yticks(y)
        ax.set_yticklabels(prov_labels, fontsize=11)
        ax.invert_yaxis()

        ax.set_xlabel("Number of Unique IPs", fontsize=11)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

        ax.legend(loc="lower right", fontsize=9, framealpha=0.9,
                  title="BGP Hijacking Case", title_fontsize=10)

        ax.set_title("Provider Vulnerability: Case Distribution per Provider",
                     fontsize=14, fontweight="bold", pad=15, color="#1B4F72")

        fig.tight_layout()
        fig.savefig(out, dpi=150, bbox_inches="tight")
        plt.close(fig)

    finally:
        matplotlib.rcParams.update(old_rc)

    return out

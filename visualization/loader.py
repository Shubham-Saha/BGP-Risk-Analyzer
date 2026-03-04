"""Load and prepare data from the BGP and Prime Intellect CSV files."""

import json
import re
from pathlib import Path

import pandas as pd

from config import CSV_FILE, PRIME_CSV_FILE


# ── BGP scan data ────────────────────────────────────────────────────────────


def load_bgp_data() -> pd.DataFrame:
    """Load scan_results.csv and derive helper columns.

    Adds: City, Region, Country, PrefixLength, MaxLengthNum, Gap.
    """
    if not CSV_FILE.exists():
        return pd.DataFrame()

    df = pd.read_csv(CSV_FILE, sep=";", encoding="utf-8-sig")

    # Parse "Location (City; Region; Country)" → separate columns
    loc = df["Location (City; Region; Country)"].str.split(r";\s*", expand=True)
    if loc.shape[1] >= 3:
        df["City"] = loc[0]
        df["Region"] = loc[1]
        df["Country"] = loc[2]
    else:
        df["City"] = df["Region"] = df["Country"] = ""

    # Prefix length: e.g. "95.216.0.0/16" → 16
    df["PrefixLength"] = (
        df["Prefix"]
        .astype(str)
        .str.extract(r"/(\d+)$")[0]
        .astype(float)
    )

    # MaxLength: e.g. "/24" → 24 or empty
    df["MaxLengthNum"] = (
        df["MaxLength"]
        .astype(str)
        .str.extract(r"/?(\d+)")[0]
        .astype(float)
    )

    # Gap for Case 2 entries
    df["Gap"] = df["MaxLengthNum"] - df["PrefixLength"]

    # Ensure Erosion Case is numeric
    df["Erosion Case?"] = pd.to_numeric(df["Erosion Case?"], errors="coerce")

    return df


# ── Prime Intellect pod data ────────────────────────────────────────────────


def _parse_availability_json(raw: str) -> dict:
    """Best-effort parse of the Availability Data JSON column.

    The data may be truncated (e.g. 1000-char limit from _safe_json),
    so we fall back to regex extraction for key fields.
    """
    if not isinstance(raw, str) or not raw.strip():
        return {}
    # Try full JSON parse first
    for text in (raw, raw.replace('""', '"')):
        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            continue
    # Fallback: regex extract key fields from truncated JSON
    result = {}
    for key in ("region", "country", "dataCenter", "provider", "gpuType",
                "gpuCount", "gpuMemory", "stockStatus"):
        m = re.search(rf'"{key}"\s*:\s*"([^"]*)"', raw)
        if m:
            result[key] = m.group(1)
            continue
        # Try numeric values
        m = re.search(rf'"{key}"\s*:\s*(\d+)', raw)
        if m:
            result[key] = int(m.group(1))
    return result


def load_prime_data() -> pd.DataFrame:
    """Load prime_pod_results.csv and extract region/country from Availability Data."""
    if not PRIME_CSV_FILE.exists():
        return pd.DataFrame()

    df = pd.read_csv(PRIME_CSV_FILE, sep=";", encoding="utf-8-sig")

    # Parse Availability Data JSON for region and country
    avail = df["Availability Data"].apply(_parse_availability_json)
    df["AvailRegion"] = avail.apply(lambda d: d.get("region", ""))
    df["AvailCountry"] = avail.apply(lambda d: d.get("country", ""))
    df["AvailDataCenter"] = avail.apply(lambda d: d.get("dataCenter", ""))

    # Ensure Price per Hour is numeric
    df["Price per Hour"] = pd.to_numeric(df["Price per Hour"], errors="coerce")

    return df


# ── Merged data ──────────────────────────────────────────────────────────────


def load_merged_data() -> pd.DataFrame:
    """Left-join Prime pod data onto BGP data via Pod IP = IP Addresses."""
    bgp = load_bgp_data()
    prime = load_prime_data()

    if bgp.empty or prime.empty:
        return pd.DataFrame()

    merged = prime.merge(
        bgp,
        left_on="Pod IP",
        right_on="IP Addresses",
        how="left",
    )
    return merged

# BGP Risk Analyzer

A research tool that discovers GPU cloud infrastructure IPs from decentralized AI providers and evaluates their vulnerability to [EROSION-style BGP attacks](https://ieeexplore.ieee.org/document/10646806). It performs automated RPKI/ROA validation, prefix analysis, and classifies each IP into one of four attack cases.

## EROSION Attack Cases

| Case | Description | Attack Vector |
|------|-------------|---------------|
| 1 | ROA exists, MaxLength = prefix length | Equal-length hijack via AS path competition |
| 2 | ROA exists, MaxLength > prefix length | Forged-origin sub-prefix hijack passes RPKI validation |
| 3 | No ROA, prefix is /24 | Equal-length hijack; sub-prefix operationally constrained (convention, not rule) |
| 4 | No ROA, prefix larger than /24 | Sub-prefix hijack possible with no RPKI barrier |

## Prerequisites

- Python 3.10 or higher
- pip

## Installation

```bash
git clone https://github.com/Shubham-Saha/BGP-Risk-Analyzer.git
cd BGP-Risk-Analyzer
```

Create and activate a virtual environment:

```bash
python -m venv venv

# Linux/macOS
source venv/bin/activate

# Windows
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Set up environment variables (only needed for Prime Intellect scans):

```bash
cp .env.example .env
# Edit .env with your Prime Intellect API key and team ID
```

## Usage

```bash
python bgp_risk_analyzer.py
```

This launches an interactive menu:

```
  [1]  Scan single IP address
  [2]  Scan IP addresses from file
  [3]  Scan single URL
  [4]  Scan URLs from file
  [5]  Prime Intellect GPU Pod Scan
  [6]  Vast.ai GPU Machine Scan
  [7]  Ping Test (Unique IPs)
  [8]  Refresh Unique IPs
  [9]  Generate Visualizations
  [10] Overlap Detection (PI vs Vast.ai)
  [11] Analysis
  [0]  Exit
```

### Quick Start

- **Option [6]** is the easiest to try — Vast.ai scan requires no API key
- **Option [1]** to analyze any single IP address
- **Option [11]** to explore analysis after scanning

### Scan Modes

**Manual scans** (options 1-4): Analyze specific IPs or URLs you provide. Each IP is queried against ipinfo.io, RIPE Stat, and RPKI validators.

**GPU provider scans** (options 5-6):
- **Prime Intellect** [5]: Provisions GPU pods via their API, extracts the underlying IP, performs BGP analysis, then terminates the pod. Requires API credentials in `.env`.
- **Vast.ai** [6]: Queries the public Vast.ai search API for available machines, deduplicates by IP, and performs BGP analysis. No authentication needed.

**Analysis** (option 11): Interactive sub-menu with:
- Crawl Overview — platform stats, performance metrics, failure summary
- Ping Status Change Analysis — tracks which IPs go online/offline
- Crawl Change Frequency — which IPs and ASNs change most across crawls
- EROSION Risk Distribution — case breakdown by IP and by ASN
- ROA Coverage Analysis — ASNs with/without ROA protection
- ASN Concentration Analysis — infrastructure distribution across ASNs

## Output

All results are saved to the `results/` directory:

| File | Description |
|------|-------------|
| `scan_results.csv` | BGP analysis for all scanned IPs (shared across platforms) |
| `unique_scan_ips.csv` | Deduplicated IPs with latest scan data |
| `prime_pod_results.csv` | Prime Intellect pod-specific details |
| `vast_machine_results.csv` | Vast.ai machine-specific details |
| `crawl_time_summary.csv` | Performance benchmarks per crawl |
| `crawl_failures_pi.csv` | Failed Prime Intellect scans |
| `crawl_failures_vast.csv` | Failed Vast.ai scans |
| `prime_pod_changes.csv` | Field changes across PI crawls |
| `vast_machine_changes.csv` | Field changes across Vast.ai crawls |
| `ip_overlap_results.csv` | IPs appearing on both platforms |
| `ip_ping_status.csv` | Ping reachability tracking over time |
| `visualizations/` | Generated charts (timestamped subfolders) |

## External APIs Used

All lookups use public APIs — no accounts needed except for Prime Intellect:

- [ipinfo.io](https://ipinfo.io) — IP geolocation and ASN lookup
- [RIPE Stat](https://stat.ripe.net) — BGP prefix overview, network info, reverse DNS
- [RIPE RPKI Validator](https://stat.ripe.net) — ROA validation
- [Vast.ai](https://vast.ai) — Public GPU machine search API
- [Prime Intellect](https://primeintellect.ai) — GPU pod provisioning API (requires key)

## License

Research use.

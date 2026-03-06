"""Build CSV row dicts from Vast.ai scan results."""

from datetime import datetime, timezone


def build_vast_csv_row(result: dict) -> dict:
    """Construct a row dict matching VAST_CSV_HEADERS from a scan result.

    The result dict is produced by vast_ai/scanner.py _scan_one() and
    contains the representative machine metadata plus BGP analysis results.
    """
    machine = result.get("machine", {})
    bgp_row = result.get("bgp_row") or {}

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    max_length_str = ""
    if bgp_row.get("MaxLength"):
        max_length_str = bgp_row["MaxLength"]
    elif bgp_row.get("_rpki_max_length") is not None:
        max_length_str = f"/{bgp_row['_rpki_max_length']}"

    return {
        "IP Address": result.get("ip", ""),
        "Machine ID": str(machine.get("machine_id", "")),
        "Host ID": str(machine.get("host_id", "")),
        "GPU Type": machine.get("gpu_name", ""),
        "Num GPUs": str(machine.get("num_gpus", "")),
        "GPU RAM (GB)": str(round(machine.get("gpu_ram", 0) / 1024, 1))
        if machine.get("gpu_ram")
        else "",
        "CPU Name": machine.get("cpu_name", ""),
        "CPU Cores": str(int(machine.get("cpu_cores_effective", 0)))
        if machine.get("cpu_cores_effective")
        else "",
        "RAM (GB)": str(round(machine.get("cpu_ram", 0) / 1024, 1))
        if machine.get("cpu_ram")
        else "",
        "Disk (GB)": str(round(machine.get("disk_space", 0), 1))
        if machine.get("disk_space")
        else "",
        "Internet Down (Mbps)": str(round(machine.get("inet_down", 0), 1))
        if machine.get("inet_down")
        else "",
        "Internet Up (Mbps)": str(round(machine.get("inet_up", 0), 1))
        if machine.get("inet_up")
        else "",
        "Geolocation": machine.get("geolocation", ""),
        "Price per Hour": str(round(machine.get("dph_total", 0), 4))
        if machine.get("dph_total")
        else "",
        "Reliability": str(round(machine.get("reliability2", 0), 4))
        if machine.get("reliability2")
        else "",
        "Static IP": str(machine.get("static_ip", "")),
        "CUDA Version": str(machine.get("cuda_max_good", "")),
        "Driver Version": str(machine.get("driver_version", "")),
        "Total Machines at IP": str(result.get("total_machines_at_ip", 1)),
        # BGP analysis fields
        "ASN": bgp_row.get("ASN", ""),
        "Hostname": bgp_row.get("Hostname", ""),
        "Company Name": bgp_row.get("Company Name", ""),
        "Range": bgp_row.get("Range", ""),
        "Location (ipinfo)": bgp_row.get("Location (City; Region; Country)", ""),
        "ROA Return": bgp_row.get("ROA Return", ""),
        "Prefix": bgp_row.get("Prefix", ""),
        "MaxLength": bgp_row.get("MaxLength", max_length_str),
        "Erosion Case?": bgp_row.get("Erosion Case?", ""),
        "Erosion Description": bgp_row.get("Erosion Description", ""),
        "Scan Timestamp": now,
        # Set by csv_writer
        "Crawl Number": "",
        "Changes in Crawl Number": "",
    }

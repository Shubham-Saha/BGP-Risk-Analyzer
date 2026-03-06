"""Vast.ai scan orchestration -- fetch listings, deduplicate IPs, parallel BGP analysis."""

import queue
import signal
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from prime_intellect.timing import CrawlTimer
from vast_ai.api import fetch_machine_listings
from vast_ai.display import display_vast_scan_start


# ── Graceful Ctrl+C ─────────────────────────────────────────────────────────

_stop_event = threading.Event()
_SENTINEL = None  # Poison pill to signal writer thread to stop


def _handle_sigint(_sig, _frame):
    """Signal handler for graceful Ctrl+C during scanning."""
    if _stop_event.is_set():
        print("\n\n  Force exit.")
        sys.exit(1)
    _stop_event.set()
    print("\n\n  Ctrl+C received. Finishing current IP(s), then stopping...")


# ── IP Deduplication ─────────────────────────────────────────────────────────


def _deduplicate_by_ip(machines: list[dict]) -> list[dict]:
    """Group machines by public_ipaddr, pick representative per IP.

    Returns a list of dicts, each with:
        ip: str
        machine: dict  (representative — highest num_gpus)
        total_machines_at_ip: int
        gpu_summary: str  (e.g. "RTX 4090 x3, A100 x2")
    """
    groups: dict[str, list[dict]] = defaultdict(list)
    for m in machines:
        ip = m.get("public_ipaddr", "").strip()
        if ip:
            groups[ip].append(m)

    ip_groups = []
    for ip, group in sorted(groups.items()):
        # Pick representative: machine with highest num_gpus
        representative = max(group, key=lambda m: m.get("num_gpus", 0))

        # Build GPU summary
        gpu_counts: dict[str, int] = defaultdict(int)
        for m in group:
            gpu_name = m.get("gpu_name", "Unknown")
            gpu_counts[gpu_name] += 1
        gpu_summary = ", ".join(
            f"{name} x{count}" if count > 1 else name
            for name, count in sorted(gpu_counts.items())
        )

        ip_groups.append({
            "ip": ip,
            "machine": representative,
            "total_machines_at_ip": len(group),
            "gpu_summary": gpu_summary,
        })

    return ip_groups


# ── Background CSV Writer ────────────────────────────────────────────────────


def _csv_writer_loop(result_queue, on_machine_done, crawl_timer):
    """Background thread: drain queue, call on_machine_done serially, record timing.

    Each item is a (index, total, result) tuple.
    Stops when it receives _SENTINEL.
    """
    while True:
        try:
            item = result_queue.get(timeout=1.0)
        except queue.Empty:
            continue
        if item is _SENTINEL:
            break
        index, total, result = item
        try:
            if on_machine_done:
                on_machine_done(index, total, result)
        except Exception as e:
            print(f"    Warning: on_machine_done failed for IP {index}: {e}")
        finally:
            bgp_row = result.get("bgp_row") or {}
            e2e = result.get("_end_to_end_seconds")
            csv_time = result.get("_csv_save_seconds", 0)
            if e2e is not None and csv_time:
                e2e = round(e2e + csv_time, 2)
            crawl_timer.record_pod({
                "spinup_seconds": None,  # No provisioning for Vast.ai
                "termination_seconds": None,
                "ipinfo_seconds": bgp_row.get("_ipinfo_seconds"),
                "prefix_seconds": bgp_row.get("_prefix_seconds"),
                "rpki_seconds": bgp_row.get("_rpki_seconds"),
                "pod_end_to_end_seconds": e2e,
                "had_error": bool(result.get("error")),
                "error_type": result.get("error_type"),
            })
            result_queue.task_done()


# ── Scan All Machines ────────────────────────────────────────────────────────


def scan_all_machines(
    bgp_analyze=None,
    on_machine_done=None,
) -> list[dict]:
    """Fetch Vast.ai listings, deduplicate by IP, and BGP-analyze each.

    Parameters
    ----------
    bgp_analyze : callable, optional
        ``f(ip: str) -> dict | None`` -- BGP analysis function.
    on_machine_done : callable, optional
        ``f(index, total, result)`` -- called after each IP is analyzed.

    Returns the list of scan results (one per unique IP).
    """
    _stop_event.clear()

    print("\n  Fetching Vast.ai machine listings...")
    machines = fetch_machine_listings()
    if not machines:
        print("  No machines returned from Vast.ai API.")
        return []

    # Deduplicate by IP
    ip_groups = _deduplicate_by_ip(machines)
    if not ip_groups:
        print("  No valid IPs found in Vast.ai listings.")
        return []

    display_vast_scan_start(len(machines), len(ip_groups))

    # Display GPU type breakdown
    gpu_types: dict[str, int] = defaultdict(int)
    for g in ip_groups:
        gpu_name = g["machine"].get("gpu_name", "Unknown")
        gpu_types[gpu_name] += 1
    print("  GPU types across unique IPs:")
    for gpu, count in sorted(gpu_types.items(), key=lambda x: -x[1])[:15]:
        print(f"    {gpu}: {count}")
    if len(gpu_types) > 15:
        print(f"    ... and {len(gpu_types) - 15} more types")

    # Interactive selection
    while True:
        print(f"\n  Which IPs to scan? Enter number(s) from 1-{len(ip_groups)}.")
        print(f"    'all'        -- scan all {len(ip_groups)} unique IPs")
        print(f"    '3'          -- scan IP #3")
        print(f"    '1,4,7'      -- scan IPs #1, #4, #7")
        print(f"    '1-20'       -- scan IPs #1 through #20")
        print(f"    '1-20,25,30' -- mix ranges and individual numbers")
        print(f"    'back'       -- return to main menu")
        scan_input = input("  Selection [all]: ").strip().lower()

        if scan_input == "back":
            print("  Returning to main menu.\n")
            return []

        break

    offerings = ip_groups  # Use 'offerings' name for consistency with selection logic
    if scan_input in ("", "all"):
        pass
    else:
        try:
            indices = []
            for token in scan_input.split(","):
                token = token.strip()
                if "-" in token:
                    start, end = token.split("-", 1)
                    indices.extend(range(int(start), int(end) + 1))
                else:
                    indices.append(int(token))
            selected = [offerings[i - 1] for i in indices if 1 <= i <= len(offerings)]
            if not selected:
                print("  No valid selections. Defaulting to all.")
            else:
                offerings = selected
        except ValueError:
            print(f"  Invalid input. Defaulting to all ({len(offerings)}).")

    # Parallelism (default higher for Vast.ai since no provisioning delay)
    parallel_input = input(
        f"\n  How many IPs to analyze in parallel? [4]: "
    ).strip()
    try:
        max_workers = int(parallel_input) if parallel_input else 4
        max_workers = max(1, min(max_workers, len(offerings)))
    except ValueError:
        max_workers = 4
        print(f"  Invalid input. Defaulting to 4.")

    if max_workers > 1:
        print(f"\n  Parallel mode: {max_workers} workers")
    else:
        print(f"\n  Sequential mode (1 worker)")

    print(f"  Will scan {len(offerings)} unique IP(s). (Press Ctrl+C to stop gracefully)")
    print("  Flow per IP: BGP analysis -> Save CSV\n")

    # Install Ctrl+C handler
    old_handler = signal.signal(signal.SIGINT, _handle_sigint)

    results = []
    result_queue = queue.Queue()
    crawl_timer = CrawlTimer(total_offerings=len(offerings), platform="Vast")
    crawl_timer.start_crawl()

    # Start background CSV writer thread
    writer_thread = threading.Thread(
        target=_csv_writer_loop,
        args=(result_queue, on_machine_done, crawl_timer),
        daemon=True,
    )
    writer_thread.start()

    total = len(offerings)

    def _scan_one(index, ip_group):
        """Worker function for a single IP. Runs in thread pool."""
        if _stop_event.is_set():
            return None

        ip = ip_group["ip"]
        gpu_summary = ip_group["gpu_summary"]
        machine_count = ip_group["total_machines_at_ip"]

        print(f"  [{index}/{total}] {ip} ({gpu_summary}, {machine_count} machine(s))")

        t_start = time.time()
        result = {
            "ip": ip,
            "machine": ip_group["machine"],
            "total_machines_at_ip": machine_count,
            "gpu_summary": gpu_summary,
            "bgp_row": None,
            "error": None,
            "error_type": None,
        }

        try:
            if bgp_analyze:
                bgp_row = bgp_analyze(ip)
                result["bgp_row"] = bgp_row
        except Exception as e:
            result["error"] = str(e)
            result["error_type"] = "bgp_analysis_error"

        result["_end_to_end_seconds"] = round(time.time() - t_start, 2)

        status = "OK" if result["bgp_row"] else "FAILED"
        print(f"  [{index}/{total}] [{status}] {ip}")

        result_queue.put((index, total, result))
        return result

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for i, ip_group in enumerate(offerings, 1):
                if _stop_event.is_set():
                    print(f"\n  Stopped by user. Submitted {i - 1}/{total} IPs.")
                    break
                future = executor.submit(_scan_one, i, ip_group)
                futures[future] = i

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result is not None:
                        results.append(result)
                except Exception as e:
                    print(f"    Warning: Worker failed: {e}")

    finally:
        result_queue.put(_SENTINEL)
        writer_thread.join(timeout=30)

        signal.signal(signal.SIGINT, old_handler)
        _stop_event.clear()

    # Save benchmark
    crawl_timer.end_crawl()
    try:
        crawl_timer.save_crawl_time_csv()
    except Exception as e:
        print(f"\n  Warning: Failed to save/display benchmark: {e}")

    print(f"\n  Scan complete. {len(results)}/{total} IPs processed.")
    return results

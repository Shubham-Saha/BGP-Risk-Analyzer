"""Pod scan orchestration — discover offerings, parallel deploy, and coordinate."""

import queue
import signal
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.error import HTTPError, URLError

from prime_intellect.api import list_pods
from prime_intellect.cleanup import cleanup_running_pods
from prime_intellect.deployer import deploy_and_analyze_pod
from prime_intellect.offerings import fetch_and_display_offerings
from prime_intellect.timing import CrawlTimer


# ── Graceful Ctrl+C ─────────────────────────────────────────────────────────

_stop_event = threading.Event()
_SENTINEL = None  # Poison pill to signal writer thread to stop


def _handle_sigint(_sig, _frame):
    """Signal handler for graceful Ctrl+C during pod scanning."""
    if _stop_event.is_set():
        print("\n\n  Force exit.")
        sys.exit(1)
    _stop_event.set()
    print("\n\n  Ctrl+C received. Finishing current pod(s), then stopping...")


# ── Background CSV Writer ────────────────────────────────────────────────────

def _csv_writer_loop(result_queue, on_pod_done, crawl_timer):
    """Background thread: drain queue, call on_pod_done serially, record timing.

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
            if on_pod_done:
                on_pod_done(index, total, result)
        except Exception as e:
            print(f"    Warning: on_pod_done failed for pod {index}: {e}")
        finally:
            # Collect all timing fields from the result for benchmarking
            # Include CSV save time in the end-to-end per pod
            bgp_row = result.get("bgp_row") or {}
            e2e = result.get("_pod_end_to_end_seconds")
            csv_time = result.get("_csv_save_seconds", 0)
            if e2e is not None and csv_time:
                e2e = round(e2e + csv_time, 2)
            crawl_timer.record_pod({
                "spinup_seconds": result.get("spinup_seconds"),
                "termination_seconds": result.get("termination_seconds"),
                "ipinfo_seconds": bgp_row.get("_ipinfo_seconds"),
                "prefix_seconds": bgp_row.get("_prefix_seconds"),
                "rpki_seconds": bgp_row.get("_rpki_seconds"),
                "pod_end_to_end_seconds": e2e,
                "had_error": bool(result.get("error")),
                "error_type": result.get("error_type"),
            })
            result_queue.task_done()


# ── Scan All Pods ────────────────────────────────────────────────────────────

def scan_all_pods(
    api_key: str,
    bgp_analyze=None,
    on_pod_done=None,
    team_id: str = "",
) -> list[dict]:
    """Discover all available GPU offerings and scan each one.

    For each offering: create pod -> wait for IP -> gather info ->
    terminate pod -> BGP analysis -> save CSV.

    Pods are provisioned in parallel (user-configurable worker count).
    CSV writing is handled by a single background thread via a queue
    to avoid file race conditions.

    Ctrl+C finishes current pod(s) gracefully, then stops.

    Parameters
    ----------
    api_key : str
        Prime Intellect API key.
    bgp_analyze : callable, optional
        ``f(ip: str) -> dict | None`` — BGP analysis function called
        after the pod is terminated.
    on_pod_done : callable, optional
        ``f(index, total, result)`` — called after each pod is fully
        processed (including termination).  Used to save CSV per-pod.
        Always called from the single background writer thread.
    team_id : str, optional
        Team ID for billing against team wallet.

    Returns the list of scan results (one per pod).
    """
    _stop_event.clear()

    # Endpoint 1: List existing pods
    try:
        existing = list_pods(api_key)
        count = existing.get("total_count", "?")
        print(f"\n  Existing pods on your account: {count}")
    except (HTTPError, URLError) as e:
        print(f"\n  Warning: Could not list existing pods: {e}")

    # Fetch and display available offerings (with refresh loop)
    offerings = fetch_and_display_offerings(api_key)
    if not offerings:
        return []

    while True:
        # Ask which offerings to scan
        print(f"\n  Which offerings to scan? Enter number(s) from the list above.")
        print(f"    'all'        — scan all {len(offerings)} offerings")
        print(f"    '3'          — scan offering #3")
        print(f"    '1,4,7'      — scan offerings #1, #4, #7")
        print(f"    '1-20'       — scan offerings #1 through #20")
        print(f"    '1-20,25,30' — mix ranges and individual numbers")
        print(f"    'refresh'    — refresh the available offerings list")
        print(f"    'back'       — return to main menu")
        scan_input = input("  Selection [all]: ").strip().lower()

        if scan_input == "refresh":
            offerings = fetch_and_display_offerings(api_key)
            if not offerings:
                return []
            continue

        if scan_input == "back":
            print("  Returning to main menu.\n")
            return []

        break

    if scan_input in ("", "all"):
        pass  # use all offerings as-is
    else:
        # Parse comma-separated tokens, each can be a number or a range (e.g. "1-20")
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

    # Ask for parallelism level
    parallel_input = input(
        f"\n  How many pods to provision in parallel? [1]: "
    ).strip()
    try:
        max_workers = int(parallel_input) if parallel_input else 1
        max_workers = max(1, min(max_workers, len(offerings)))
    except ValueError:
        max_workers = 1
        print(f"  Invalid input. Defaulting to 1 (sequential).")

    if max_workers > 1:
        print(f"\n  Parallel mode: {max_workers} workers")
    else:
        print(f"\n  Sequential mode (1 worker)")

    print(f"  Will scan {len(offerings)} offering(s). (Press Ctrl+C to stop gracefully)")
    print("  Flow per offering: Create pod -> Wait for IP -> Gather info")
    print("  -> Terminate pod -> BGP analysis -> Save CSV\n")

    # Install Ctrl+C handler for graceful stop
    old_handler = signal.signal(signal.SIGINT, _handle_sigint)

    results = []
    result_queue = queue.Queue()
    crawl_timer = CrawlTimer(total_offerings=len(offerings))
    crawl_timer.start_crawl()

    # Start background CSV writer thread
    writer_thread = threading.Thread(
        target=_csv_writer_loop,
        args=(result_queue, on_pod_done, crawl_timer),
        daemon=True,
    )
    writer_thread.start()

    total = len(offerings)

    def _scan_one(index, offering):
        """Worker function for a single offering. Runs in thread pool."""
        if _stop_event.is_set():
            return None

        gpu = offering.get("gpuType", offering.get("gpu_type", "?"))
        provider = offering.get("provider", offering.get("providerType", "?"))
        region = offering.get("region", "?")
        price = offering.get("prices", {})
        on_demand = price.get("onDemand", "?") if isinstance(price, dict) else "?"

        print(f"  [{index}/{total}] {gpu} / {provider} / {region} (${on_demand}/hr)")

        t_pod_start = time.time()
        result = deploy_and_analyze_pod(
            api_key, offering, bgp_analyze=bgp_analyze, team_id=team_id
        )
        result["_pod_end_to_end_seconds"] = round(time.time() - t_pod_start, 2)

        status = "OK" if result["pod_ip"] else "FAILED"
        ip_str = f"IP: {result['pod_ip']}" if result["pod_ip"] else "No IP obtained"
        print(f"  [{index}/{total}] [{status}] {ip_str}")

        # Enqueue result for background CSV writing (non-blocking)
        result_queue.put((index, total, result))
        return result

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for i, offering in enumerate(offerings, 1):
                if _stop_event.is_set():
                    print(f"\n  Stopped by user. Submitted {i - 1}/{total} offerings.")
                    break
                future = executor.submit(_scan_one, i, offering)
                futures[future] = i

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result is not None:
                        results.append(result)
                except Exception as e:
                    print(f"    Warning: Worker failed: {e}")

    finally:
        # Signal the writer thread to finish, then wait for it
        result_queue.put(_SENTINEL)
        writer_thread.join(timeout=30)

        # Restore original signal handler
        signal.signal(signal.SIGINT, old_handler)
        _stop_event.clear()

    # Record crawl end time and save benchmark CSV
    crawl_timer.end_crawl()
    try:
        crawl_timer.save_crawl_time_csv()
    except Exception as e:
        print(f"\n  Warning: Failed to save/display benchmark: {e}")

    # Final safety check: terminate any pods still running
    print("\n  Running pod cleanup check...")
    cleanup_running_pods(api_key)

    print(f"\n  Scan complete. {len(results)}/{total} offerings processed.")
    return results

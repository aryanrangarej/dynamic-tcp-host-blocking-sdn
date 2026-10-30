#!/usr/bin/env python3
"""
Low-Level TCP Socket Client & Traffic Generator
Team 10 - UE25CS243A Computer Networks Mini-Project

Supports configurable traffic generation modes:
1. Normal Client Traffic (h1)
2. High-rate Malicious Burst / SYN Attack Traffic (h2)
3. Concurrent Legitimate Traffic (h3)
4. Post-Recovery Verification Traffic (h2 post-cooldown)

Measures connection success rate, latency, timeouts, and records CSV benchmarks.
"""

import socket
import time
import argparse
import os
import csv
import sys
import config


def run_traffic_client(target_host, target_port, rate, duration, label, csv_path=None):
    """
    Executes a stream of TCP connection attempts at a specified frequency.
    
    :param target_host: Server IP to connect to
    :param target_port: Server TCP port
    :param rate: Number of connection attempts per second
    :param duration: Total test execution time in seconds
    :param label: Identifier for reporting and CSV logging
    :param csv_path: Filepath to append benchmark metrics
    """
    start_time = time.monotonic()
    end_time = start_time + duration
    interval = 1.0 / rate if rate > 0 else 0

    stats = {
        'attempts': 0,
        'success': 0,
        'timeouts': 0,
        'refused': 0,
        'errors': 0
    }
    latencies_ms = []
    first_failure_time = None

    print(f"[{label}] Initiating traffic stream to {target_host}:{target_port} "
          f"({rate} conn/s for {duration}s)...")

    while time.monotonic() < end_time:
        iteration_start = time.monotonic()
        stats['attempts'] += 1

        try:
            # Low-level TCP socket creation
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                # 0.4 second timeout to detect dropped packets swiftly
                sock.settimeout(0.4)
                conn_start = time.monotonic()
                sock.connect((target_host, target_port))
                
                # Send application payload
                sock.sendall(b"PING: Team10-SDN-Test\n")
                response = sock.recv(128)
                
                if not response:
                    raise OSError("Empty response received from server")

                elapsed_ms = (time.monotonic() - conn_start) * 1000.0
                stats['success'] += 1
                latencies_ms.append(elapsed_ms)

        except socket.timeout:
            stats['timeouts'] += 1
            if first_failure_time is None:
                first_failure_time = round(time.monotonic() - start_time, 2)
        except ConnectionRefusedError:
            stats['refused'] += 1
            if first_failure_time is None:
                first_failure_time = round(time.monotonic() - start_time, 2)
        except OSError as e:
            stats['errors'] += 1
            if first_failure_time is None:
                first_failure_time = round(time.monotonic() - start_time, 2)

        # Rate control pacing
        spent = time.monotonic() - iteration_start
        sleep_duration = max(0.0, interval - spent)
        if sleep_duration > 0:
            time.sleep(sleep_duration)

    # Compute aggregate statistics
    attempts = stats['attempts']
    success = stats['success']
    success_rate = (success / attempts * 100.0) if attempts > 0 else 0.0
    avg_latency = (sum(latencies_ms) / len(latencies_ms)) if latencies_ms else 0.0

    print(f"[{label}] Finished: Attempts={attempts}, Success={success}, "
          f"Timeouts={stats['timeouts']}, Refused={stats['refused']}, "
          f"Success Rate={success_rate:.2f}%, Avg Latency={avg_latency:.2f}ms")

    # Append to CSV if requested
    if csv_path:
        file_exists = os.path.exists(csv_path) and os.path.getsize(csv_path) > 0
        with open(csv_path, 'a', newline='') as f:
            fieldnames = [
                'label', 'target', 'attempts', 'success', 'timeouts',
                'refused', 'errors', 'success_rate', 'avg_ms', 'first_failure_s'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerow({
                'label': label,
                'target': f"{target_host}:{target_port}",
                'attempts': attempts,
                'success': success,
                'timeouts': stats['timeouts'],
                'refused': stats['refused'],
                'errors': stats['errors'],
                'success_rate': round(success_rate, 2),
                'avg_ms': round(avg_latency, 2),
                'first_failure_s': first_failure_time if first_failure_time is not None else ""
            })

    return stats


def main():
    parser = argparse.ArgumentParser(description="Low-Level TCP Socket Client / Traffic Generator")
    parser.add_argument("--host", default=config.SERVER_IP, help=f"Target Host IP (default: {config.SERVER_IP})")
    parser.add_argument("--port", type=int, default=config.SERVER_PORT, help=f"Target Host Port (default: {config.SERVER_PORT})")
    parser.add_argument("--rate", type=float, default=1.0, help="Connections per second (default: 1.0)")
    parser.add_argument("--duration", type=float, default=5.0, help="Duration in seconds (default: 5.0)")
    parser.add_argument("--label", default="CLIENT", help="Experiment label for output logging")
    parser.add_argument("--csv", default=None, help="CSV output filename")

    args = parser.parse_args()

    if args.rate <= 0 or args.duration <= 0:
        sys.exit("[ERROR] Rate and duration must be positive values.")

    run_traffic_client(
        target_host=args.host,
        target_port=args.port,
        rate=args.rate,
        duration=args.duration,
        label=args.label,
        csv_path=args.csv
    )


if __name__ == "__main__":
    main()

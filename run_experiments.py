#!/usr/bin/env python3
"""
Automated Test & Benchmark Runner
Team 10 - UE25CS243A Computer Networks Mini-Project

Orchestrates two comparative experiments:
1. Static Baseline: Mininet with standard Open vSwitch (no dynamic SDN defense).
2. Dynamic SDN: Mininet + OS-Ken Controller (real-time detection, DROP rule, recovery).

Generates `benchmark_results.csv` and verifies all project rubric criteria.
"""

import os
import sys
import time
import subprocess
import signal
import config

from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.log import setLogLevel
from topology import DynamicBlockingTopology


def run_command(cmd, shell=False):
    """Executes a system shell command safely."""
    return subprocess.run(
        cmd,
        shell=shell,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )


def clean_environment():
    """Flushes Mininet state and lingering OVS interfaces."""
    run_command(['mn', '-c'])


def wait_for_pattern_in_file(filepath, pattern, timeout=40):
    """Polls a log file until a specified pattern appears or timeout occurs."""
    start = time.time()
    while time.time() - start < timeout:
        if os.path.exists(filepath):
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
                if pattern in content:
                    return True
        time.sleep(0.5)
    return False


def execute_test_suite(enable_sdn_controller=False):
    """
    Executes a single test iteration (either Baseline or Dynamic SDN).
    
    :param enable_sdn_controller: If True, launches OS-Ken controller. If False, runs pure OVS.
    """
    mode_name = "DYNAMIC-SDN" if enable_sdn_controller else "STATIC-BASELINE"
    print("\n" + "=" * 70)
    print(f"  STARTING EXPERIMENT: {mode_name}")
    print("=" * 70)

    controller_process = None
    log_fd = None

    try:
        # Step 1: Start Controller if enabled
        if enable_sdn_controller:
            print("[SETUP] Launching OS-Ken SDN Controller (sdn_controller.py)...")
            log_fd = open(config.LOG_FILE, 'w')
            controller_cmd = [
                'osken-manager',
                '--ofp-tcp-listen-port', str(config.CONTROLLER_PORT),
                'sdn_controller.py'
            ]
            controller_process = subprocess.Popen(
                controller_cmd,
                stdout=log_fd,
                stderr=subprocess.STDOUT,
                preexec_fn=os.setsid
            )
            time.sleep(3)  # Wait for controller socket initialization

        # Step 2: Initialize Mininet Network
        print("[SETUP] Building Mininet network from topology.py...")
        topo = DynamicBlockingTopology()

        if enable_sdn_controller:
            net = Mininet(
                topo=topo,
                switch=OVSSwitch,
                controller=RemoteController('c0', port=config.CONTROLLER_PORT),
                autoSetMacs=True
            )
        else:
            # Standalone OVS switch without external controller
            net = Mininet(
                topo=topo,
                switch=OVSSwitch,
                controller=None,
                autoSetMacs=True
            )

        net.start()
        s1 = net.get('s1')

        # Configure switch flow pipeline
        if not enable_sdn_controller:
            # In baseline mode, add simple NORMAL forwarding rule
            s1.cmd('ovs-ofctl -O OpenFlow13 del-flows s1')
            s1.cmd('ovs-ofctl -O OpenFlow13 add-flow s1 priority=0,actions=normal')

        h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')

        # Step 3: Launch TCP Server on h4
        print(f"[SETUP] Starting low-level TCP Server on {h4.IP()}:{config.SERVER_PORT}...")
        server_process = h4.popen(
            ['python3', 'tcp_server.py', '--host', h4.IP(), '--port', str(config.SERVER_PORT)]
        )
        time.sleep(1)

        # Step 4: Run Traffic Scenarios
        prefix = "DYNAMIC" if enable_sdn_controller else "BASELINE"

        # 4a. Normal client (h1) test
        print(f"\n[PHASE 1] Executing Normal Client Traffic ({h1.name})...")
        res_normal = h1.cmd(
            f"python3 tcp_client.py --host {h4.IP()} --port {config.SERVER_PORT} "
            f"--rate 1 --duration 3 --label {prefix}-NORMAL --csv {config.RESULTS_CSV}"
        )
        print(res_normal.strip())

        # 4b. Legitimate client (h3) and Attacker (h2) test
        print(f"\n[PHASE 2] Executing Attacker ({h2.name}) and Concurrent Legitimate ({h3.name})...")
        
        # Start legitimate client on h3 in background (1 conn/sec for 6 sec)
        legit_proc = h3.popen(
            f"python3 tcp_client.py --host {h4.IP()} --port {config.SERVER_PORT} "
            f"--rate 1 --duration 6 --label {prefix}-LEGITIMATE --csv {config.RESULTS_CSV}".split()
        )

        # Run attack traffic on h2 in foreground (20 conn/sec for 6 sec = 120 attempts)
        res_attack = h2.cmd(
            f"python3 tcp_client.py --host {h4.IP()} --port {config.SERVER_PORT} "
            f"--rate 20 --duration 6 --label {prefix}-ATTACK --csv {config.RESULTS_CSV}"
        )
        print(res_attack.strip())

        # Wait for legitimate client to finish
        legit_proc.wait()

        # Step 5: Verification in Dynamic SDN Mode
        if enable_sdn_controller:
            print("\n[VERIFICATION] Inspecting OpenFlow flow tables on s1...")
            flows = s1.cmd('ovs-ofctl -O OpenFlow13 dump-flows s1')
            drop_rules = [line for line in flows.splitlines() if 'actions=drop' in line]
            
            print("Active DROP Rules in Switch:")
            for rule in drop_rules:
                print("  " + rule.strip())

            # Confirm attacker IP is dropped and legitimate host is not
            if not any(f'nw_src={h2.IP()}' in r for r in drop_rules):
                raise RuntimeError(f"[FAIL] Expected DROP rule for {h2.IP()} was not found!")
            if any(f'nw_src={h3.IP()}' in r for r in drop_rules):
                raise RuntimeError(f"[FAIL] Legitimate host {h3.IP()} was falsely blocked!")
            print("[PASS] Dynamic DROP rule strictly isolated attacker h2.")

            # Await automated unblocking
            print(f"\n[COOLDOWN] Waiting for {config.BLOCK_DURATION_SECONDS}s unblock timer...")
            recovery_found = wait_for_pattern_in_file(
                config.LOG_FILE,
                f"[UNBLOCK] Host {h2.IP()}",
                timeout=config.BLOCK_DURATION_SECONDS + 15
            )
            if not recovery_found:
                raise RuntimeError("[FAIL] Host recovery did not trigger within deadline!")
            print(f"[PASS] Host {h2.IP()} unblocked successfully.")

            # Test h2 post-recovery
            print(f"\n[PHASE 3] Testing Host {h2.name} Post-Recovery Connectivity...")
            res_recovery = h2.cmd(
                f"python3 tcp_client.py --host {h4.IP()} --port {config.SERVER_PORT} "
                f"--rate 1 --duration 3 --label RECOVERY-H2 --csv {config.RESULTS_CSV}"
            )
            print(res_recovery.strip())

    finally:
        print("\n[CLEANUP] Stopping Mininet and terminating background processes...")
        try:
            server_process.terminate()
            server_process.wait(timeout=2)
        except Exception:
            pass

        try:
            net.stop()
        except Exception:
            pass

        if controller_process:
            try:
                os.killpg(controller_process.pid, signal.SIGTERM)
                controller_process.wait(timeout=3)
            except Exception:
                pass

        if log_fd:
            log_fd.close()

        clean_environment()
        print(f"[CLEANUP] Experiment {mode_name} completed.\n")


def main():
    if os.geteuid() != 0:
        sys.exit("[ERROR] Mininet requires root privileges. Please run: sudo python3 run_experiments.py")

    setLogLevel('warning')

    # Remove stale results if present
    if os.path.exists(config.RESULTS_CSV):
        os.remove(config.RESULTS_CSV)

    clean_environment()

    # 1. Run Static Baseline
    execute_test_suite(enable_sdn_controller=False)

    # 2. Run Dynamic SDN
    execute_test_suite(enable_sdn_controller=True)

    print("\n" + "=" * 70)
    print(f"  BENCHMARK COMPLETE! Results saved to {config.RESULTS_CSV}")
    print("=" * 70)
    if os.path.exists(config.RESULTS_CSV):
        with open(config.RESULTS_CSV, 'r') as f:
            print(f.read())


if __name__ == '__main__':
    main()

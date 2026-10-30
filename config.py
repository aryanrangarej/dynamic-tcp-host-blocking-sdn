"""
Central Configuration for Dynamic Host Blocking System
Team 10 - UE25CS243A Computer Networks Mini-Project
"""

# Network Architecture Configuration
SERVER_IP = "10.0.0.4"
SERVER_PORT = 5001

HOSTS_CONFIG = {
    "h1": {"ip": "10.0.0.1/24", "mac": "00:00:00:00:00:01", "role": "Normal Client"},
    "h2": {"ip": "10.0.0.2/24", "mac": "00:00:00:00:00:02", "role": "Suspicious / Attacker Client"},
    "h3": {"ip": "10.0.0.3/24", "mac": "00:00:00:00:00:03", "role": "Legitimate Background Client"},
    "h4": {"ip": "10.0.0.4/24", "mac": "00:00:00:00:00:04", "role": "TCP Application Server"},
}

# SDN & OpenFlow Parameters
OF_VERSION = "OpenFlow13"
CONTROLLER_PORT = 6653

# OpenFlow Flow Priorities
PRIORITY_DEFAULT = 0          # Default table-miss forwarding (NORMAL)
PRIORITY_SYN_MONITOR = 100    # Copy TCP SYN packets to controller
PRIORITY_DROP_BLOCK = 200     # Drop all packets from blocked source IP

# Anomaly Detection & Blocking Thresholds
SYN_RATE_WINDOW_SECONDS = 5.0     # Sliding time window for rate tracking
SYN_THRESHOLD_COUNT = 8           # Maximum allowed SYNs within the window
BLOCK_DURATION_SECONDS = 25.0     # Time (seconds) a malicious host remains blocked
SWITCH_HARD_TIMEOUT_OFFSET = 4.0  # Extra seconds for switch hard timeout (safety fallback)
FLOW_STATS_INTERVAL = 4.0         # Interval for requesting OpenFlow port/flow counters

# Logging and Output Files
LOG_FILE = "controller_runtime.log"
RESULTS_CSV = "benchmark_results.csv"

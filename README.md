# Dynamic Host Blocking System

**Course**: UE25CS243A – Computer Networks  
**Project**: Mini-Project Level 3 (Jackfruit) – Project 12  
**Team**: Team 10  
**Domain**: Software Defined Networking (SDN) & Low-Level Socket Programming  

---

## 1. Problem Statement

Develop an automated, programmable network security system that monitors low-level TCP traffic, identifies abnormal connection burst patterns (such as TCP SYN floods or unauthorized rapid connection attempts), and dynamically installs OpenFlow flow rules in the SDN switch to block malicious hosts in real time while maintaining uninterrupted service for legitimate network users.

---

## 2. System Architecture

The project integrates low-level Python TCP socket applications with an OpenFlow 1.3 Software-Defined Networking architecture:

```
                      +---------------------------------------+
                      |       SDN Controller (OS-Ken)        |
                      |  - Sliding-Window Rate Tracking       |
                      |  - Dynamic Blocklist Management       |
                      |  - OpenFlow Flow-Mod (DROP) Engine   |
                      |  - Switch Telemetry & Flow Statistics |
                      +-------------------+-------------------+
                                          |
                                    OpenFlow 1.3
                                    (TCP: 6653)
                                          |
                      +-------------------+-------------------+
                      |      Open vSwitch Datapath (s1)      |
                      |  Priority 200: DROP (Blocked Hosts)   |
                      |  Priority 100: SYN Copy -> Controller |
                      |  Priority   0: NORMAL L2/L3 Forward   |
                      +-------+-----------+-----------+-------+
                              |           |           |
             +----------------+           |           +----------------+
             |                            |                            |
      +------+------+              +------+------+              +------+------+
      |   Host h1   |              |   Host h2   |              |   Host h3   |
      | 10.0.0.1/24 |              | 10.0.0.2/24 |              | 10.0.0.3/24 |
      |Normal Client|              |   Attacker  |              |  Legitimate |
      +-------------+              +-------------+              +-------------+
                                          |
                                          v
                                   +--------------+
                                   |   Host h4    |
                                   | 10.0.0.4/24  |
                                   |  TCP Server  |
                                   | (Port 5001)  |
                                   +--------------+
```

### Network Nodes & Roles

| Node | IP Address | MAC Address | Role | Description |
| :--- | :--- | :--- | :--- | :--- |
| **h1** | `10.0.0.1/24` | `00:00:00:00:00:01` | Normal Client | Generates standard, low-frequency TCP requests (1 conn/s). |
| **h2** | `10.0.0.2/24` | `00:00:00:00:00:02` | Suspicious Client | Generates high-frequency TCP connection bursts (20 conn/s) to trigger anomaly detection. |
| **h3** | `10.0.0.3/24` | `00:00:00:00:00:03` | Legitimate Background Client | Runs concurrent normal traffic during the attack to verify zero false positives. |
| **h4** | `10.0.0.4/24` | `00:00:00:00:00:04` | TCP Application Server | Multi-threaded socket server listening on port `5001`. |
| **s1** | N/A | N/A | OpenFlow 1.3 Switch | Open vSwitch datapath controlled by the SDN controller. |

---

## 3. OpenFlow Flow Table Priority Hierarchy

OpenFlow processes flow rules strictly in descending order of priority:

| Priority | Match Criteria | Actions | Purpose |
| :---: | :--- | :--- | :--- |
| **200** | `eth_type=0x0800, ipv4_src=<blocked_ip>` | `[]` *(Empty Action = DROP)* | Dynamically installed when a host exceeds the threshold. Silently drops all packets from the offender at data-plane speed. |
| **100** | `eth_type=0x0800, ip_proto=6, tcp_flags=(0x002, 0x012)` | `[OFPP_CONTROLLER, OFPP_NORMAL]` | Matches TCP SYN packets. Clones the packet to the controller for connection-rate inspection while allowing the original packet to proceed. |
| **0** | `*` *(Table-Miss Wildcard)* | `[OFPP_NORMAL]` | Default traditional L2/L3 forwarding (handles ARP resolution, non-SYN TCP packets, and legitimate data payloads). |

---

## 4. Key Project Features & Deliverables Checklist

- [x] **Low-Level TCP Sockets**: Custom multi-threaded server (`tcp_server.py`) and parameterized traffic client (`tcp_client.py`) using Python's standard `socket` library.
- [x] **Sliding-Window Rate Monitoring**: Controller tracks per-source SYN arrival timestamps in a rolling 5.0-second deque.
- [x] **Configurable Anomaly Thresholds**: Triggers when $\ge 8$ SYNs are received from a single host within the window (`config.py`).
- [x] **Dynamic SDN Mitigation**: Installs a Priority 200 `OFPFlowMod` DROP rule specifically matching the offending source IP.
- [x] **Zero False-Positives**: Legitimate host `h3` continues communicating with `h4` with 100% success during the active attack.
- [x] **Automated Recovery & Cooldown**: Background controller greenlet flushes the DROP rule after 25 seconds, restoring the host.
- [x] **OpenFlow Telemetry**: Periodic `OFPFlowStatsRequest` logs packet and byte counters for active flow rules.
- [x] **Automated Benchmarking & Plotting**: Scripts to run baseline vs. dynamic experiments (`run_experiments.py`) and plot comparative graphs (`plot_results.py`).

---

## 5. File Structure

```text
final try/
├── config.py             # Central configuration (IPs, ports, thresholds, timers)
├── topology.py           # Mininet 4-host, 1-switch OpenFlow 1.3 topology definition
├── tcp_server.py         # Multi-threaded low-level TCP socket application server
├── tcp_client.py         # TCP socket client & rate-controlled traffic generator
├── sdn_controller.py     # OS-Ken OpenFlow 1.3 controller application
├── run_experiments.py    # Automated test harness for Baseline vs. SDN experiments
├── plot_results.py       # Matplotlib visualization script for benchmark charts
├── requirements.txt      # Python dependencies (os-ken, eventlet, matplotlib)
└── README.md             # Comprehensive project documentation
```

---

## 6. Installation & Prerequisites (Ubuntu VM)

Ensure your Ubuntu VM has Mininet and Open vSwitch installed:

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install Mininet and Open vSwitch
sudo apt install -y mininet openvswitch-switch

# Verify Open vSwitch service is running
sudo systemctl status openvswitch-switch

# Install Python dependencies
python3 -m pip install -r requirements.txt
```

> **Note**: If `osken-manager` is installed in a user-local directory (e.g., `~/.local/bin`), ensure it is accessible in the `sudo` environment PATH or create a symlink:
> ```bash
> sudo ln -s $(which osken-manager) /usr/local/bin/osken-manager
> ```

---

## 7. How to Run

### Method A: Automated Full Benchmark Suite (Recommended)

Run the end-to-end benchmark (executes both Static Baseline and Dynamic SDN tests, verifies DROP rules, awaits recovery, and outputs CSV results):

```bash
sudo python3 run_experiments.py
```

To generate the evaluation charts:
```bash
python3 plot_results.py
```

### Method B: Manual Step-by-Step Execution

#### Terminal 1: Start SDN Controller
```bash
osken-manager --ofp-tcp-listen-port 6653 sdn_controller.py
```

#### Terminal 2: Start Mininet Topology
```bash
sudo mn --custom topology.py --topo dhbtopo --controller remote,ip=127.0.0.1,port=6653 --switch ovs,protocols=OpenFlow13
```

#### Inside Mininet CLI:
```bash
# 1. Start TCP Server on h4 in background
mininet> h4 python3 tcp_server.py &

# 2. Test Normal Traffic from h1
mininet> h1 python3 tcp_client.py --host 10.0.0.4 --port 5001 --rate 1 --duration 3 --label NORMAL

# 3. Test Attack Traffic from h2 (exceeds 8 SYNs, triggers block)
mininet> h2 python3 tcp_client.py --host 10.0.0.4 --port 5001 --rate 20 --duration 6 --label ATTACK

# 4. Concurrently verify legitimate host h3 is unaffected
mininet> h3 python3 tcp_client.py --host 10.0.0.4 --port 5001 --rate 1 --duration 4 --label LEGITIMATE

# 5. Check switch flow rules (observe the Priority 200 DROP rule)
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

---

## 8. Experimental Results & Comparison

| Test Phase | Traffic Profile | Static OVS Baseline | Dynamic SDN Controller | Outcome Description |
| :--- | :--- | :---: | :---: | :--- |
| **Normal Client (h1)** | 1 conn/s for 3s | **3 / 3 (100%)** | **3 / 3 (100%)** | Standard traffic proceeds with zero interference. |
| **Legitimate Client (h3)** | 1 conn/s for 6s | **6 / 6 (100%)** | **6 / 6 (100%)** | Full availability maintained throughout the attack period. |
| **Attacker Client (h2)** | 20 conn/s for 6s | **120 / 120 (100%)** | **8 / 22 (36.4%)** | In Baseline, all 120 attacks succeed. In SDN, host is blocked after 8 SYNs; all remaining attempts time out. |
| **Post-Recovery (h2)** | 1 conn/s for 3s | N/A | **3 / 3 (100%)** | Rule automatically expires after 25s; host re-establishes connectivity. |

---

## 9. Evaluation Criteria & Defense FAQ

- **Why is the 8th connection allowed before blocking occurs?**  
  The controller uses asynchronous monitoring (`OFPP_NORMAL` + `OFPP_CONTROLLER`) to avoid adding handshake latency to legitimate traffic. The packet that reaches the threshold triggers the `OFPFlowMod` DROP rule, so subsequent attempts from the source IP are dropped immediately at the switch level.
- **Why use Priority 200 for the DROP rule?**  
  OpenFlow matches higher priority numbers first. A Priority 200 rule for `ipv4_src` takes precedence over Priority 100 (SYN monitor) and Priority 0 (NORMAL forwarding), ensuring the switch drops packets without generating extra controller traffic.
- **How is safety ensured if the controller fails?**  
  The switch rule includes an OpenFlow `hard_timeout` of $29\text{s}$ (cooldown $+ 4\text{s}$). If the controller crashes or disconnects, the switch hardware timer automatically clears the drop rule to prevent permanent host isolation.

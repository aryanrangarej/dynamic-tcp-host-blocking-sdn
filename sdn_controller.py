#!/usr/bin/env python3
"""
SDN Controller Application: Dynamic Host Blocking System
Team 10 - UE25CS243A Computer Networks Mini-Project

Controller Stack: OS-Ken / OpenFlow 1.3
Key Responsibilities:
1. Installs table-miss and SYN-monitoring OpenFlow rules.
2. Intercepts TCP SYN requests and tracks connection rates per source IP.
3. Identifies abnormal connection patterns exceeding configured thresholds.
4. Dynamically installs high-priority OpenFlow DROP rules to isolate malicious hosts.
5. Implements automated rule expiry and host recovery.
6. Periodically polls and logs switch flow statistics (counters and bytes).
"""

from collections import defaultdict, deque
import time
import logging

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib import hub
from os_ken.lib.packet import packet, ipv4
from os_ken.ofproto import ofproto_v1_3

import config


class DynamicHostBlockerController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapath = None
        self.syn_history = defaultdict(deque)  # IP -> deque of timestamps
        self.blocked_hosts = {}                # IP -> expiry timestamp
        
        # Configure logging format
        self.logger.setLevel(logging.INFO)
        self.logger.info("=" * 65)
        self.logger.info("Initializing Dynamic Host Blocking SDN Controller (OpenFlow 1.3)")
        self.logger.info(f"Threshold: {config.SYN_THRESHOLD_COUNT} SYNs in {config.SYN_RATE_WINDOW_SECONDS}s | "
                         f"Block Duration: {config.BLOCK_DURATION_SECONDS}s")
        self.logger.info("=" * 65)

        # Launch periodic background monitor for expirations and flow statistics
        self.monitor_thread = hub.spawn(self._periodic_monitor_loop)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Triggered when Open vSwitch handshake completes.
        Installs initial proactive OpenFlow rules.
        """
        self.datapath = ev.msg.datapath
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser

        self.logger.info(f"[SWITCH] Connected to Datapath ID: {self.datapath.id:016x}")

        # Rule 1: Priority 0 (Default Table-Miss) -> Forward via OVS NORMAL L2/L3 pipeline
        match_all = parser.OFPMatch()
        actions_normal = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self._add_flow(
            priority=config.PRIORITY_DEFAULT,
            match=match_all,
            actions=actions_normal
        )
        self.logger.info("[OF-SETUP] Priority 0 rule installed (NORMAL L2/L3 forwarding).")

        # Rule 2: Priority 100 (SYN Monitoring) -> Match TCP SYN packets
        # tcp_flags=(0x002, 0x012) matches SYN flag set (bit 1) and ACK flag cleared (bit 4)
        match_syn = parser.OFPMatch(
            eth_type=0x0800,           # IPv4
            ip_proto=6,                # TCP
            tcp_flags=(0x002, 0x012)   # SYN=1, ACK=0
        )
        actions_syn = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER),
            parser.OFPActionOutput(ofproto.OFPP_NORMAL)
        ]
        self._add_flow(
            priority=config.PRIORITY_SYN_MONITOR,
            match=match_syn,
            actions=actions_syn
        )
        self.logger.info("[OF-SETUP] Priority 100 rule installed (TCP SYN clone to Controller).")

    def _add_flow(self, priority, match, actions, hard_timeout=0):
        """Helper to construct and send an OFPFlowMod message to the switch."""
        parser = self.datapath.ofproto_parser
        ofproto = self.datapath.ofproto

        instructions = []
        if actions:
            instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        flow_mod = parser.OFPFlowMod(
            datapath=self.datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            hard_timeout=int(hard_timeout)
        )
        self.datapath.send_msg(flow_mod)

    def _remove_flow(self, priority, match):
        """Helper to delete matching flow entries from the switch."""
        parser = self.datapath.ofproto_parser
        ofproto = self.datapath.ofproto

        flow_mod = parser.OFPFlowMod(
            datapath=self.datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            priority=priority,
            match=match
        )
        self.datapath.send_msg(flow_mod)

    def block_host(self, host_ip):
        """Installs a Priority 200 DROP rule for the offending source IP."""
        parser = self.datapath.ofproto_parser
        match_attacker = parser.OFPMatch(eth_type=0x0800, ipv4_src=host_ip)

        # Switch hard_timeout acts as a safety-net if controller disconnects
        switch_timeout = int(config.BLOCK_DURATION_SECONDS + config.SWITCH_HARD_TIMEOUT_OFFSET)

        # Empty actions list produces a DROP flow rule in OpenFlow 1.3
        self._add_flow(
            priority=config.PRIORITY_DROP_BLOCK,
            match=match_attacker,
            actions=[],
            hard_timeout=switch_timeout
        )

        # Record in dynamic blocklist with expiry timestamp
        self.blocked_hosts[host_ip] = time.monotonic() + config.BLOCK_DURATION_SECONDS
        self.logger.warning(
            f"[SDN DROP RULE] [BLOCKLIST] Host {host_ip} blocked dynamically for "
            f"{config.BLOCK_DURATION_SECONDS}s (Priority {config.PRIORITY_DROP_BLOCK})."
        )

    def unblock_host(self, host_ip):
        """Removes the Priority 200 DROP rule, restoring host connectivity."""
        parser = self.datapath.ofproto_parser
        match_attacker = parser.OFPMatch(eth_type=0x0800, ipv4_src=host_ip)

        self._remove_flow(
            priority=config.PRIORITY_DROP_BLOCK,
            match=match_attacker
        )
        self.logger.info(f"[UNBLOCK] Host {host_ip} cooldown period expired; DROP rule removed.")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Handles incoming PACKET_IN notifications for TCP SYN packets.
        Calculates sliding window rates and triggers dynamic mitigation.
        """
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        ip_header = pkt.get_protocol(ipv4.ipv4)

        if not ip_header:
            return

        src_ip = ip_header.src

        # If already blocked, let data plane drop it silently
        if src_ip in self.blocked_hosts:
            return

        now = time.monotonic()
        history = self.syn_history[src_ip]
        history.append(now)

        # Prune timestamps older than sliding window
        while history and (now - history[0] > config.SYN_RATE_WINDOW_SECONDS):
            history.popleft()

        current_count = len(history)
        self.logger.info(
            f"[RATE-MONITOR] Host {src_ip} -> {current_count}/{config.SYN_THRESHOLD_COUNT} "
            f"SYNs in last {config.SYN_RATE_WINDOW_SECONDS}s"
        )

        # Check threshold condition
        if current_count >= config.SYN_THRESHOLD_COUNT:
            self.logger.warning(
                f"[ALERT] Abnormal TCP activity detected! Host {src_ip} exceeded threshold "
                f"({current_count} SYNs)."
            )
            self.block_host(src_ip)

    def _periodic_monitor_loop(self):
        """Periodically audits blocklist expirations and requests switch flow counters."""
        while True:
            now = time.monotonic()

            # Check expired blocks
            expired_ips = [ip for ip, expiry in self.blocked_hosts.items() if now >= expiry]
            for ip in expired_ips:
                self.unblock_host(ip)
                del self.blocked_hosts[ip]
                self.syn_history[ip].clear()

            # Request switch flow statistics if switch is connected
            if self.datapath:
                parser = self.datapath.ofproto_parser
                req = parser.OFPFlowStatsRequest(self.datapath)
                self.datapath.send_msg(req)

            hub.sleep(config.FLOW_STATS_INTERVAL)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Logs packet and byte counters for active OpenFlow entries."""
        for flow in ev.msg.body:
            if flow.priority in (config.PRIORITY_SYN_MONITOR, config.PRIORITY_DROP_BLOCK):
                self.logger.info(
                    f"[FLOW-STAT] Priority={flow.priority:3d} | "
                    f"Packets={flow.packet_count:6d} | Bytes={flow.byte_count:8d}"
                )

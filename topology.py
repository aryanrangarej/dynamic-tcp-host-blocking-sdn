#!/usr/bin/env python3
"""
Custom Mininet Topology for Dynamic Host Blocking System
Team 10 - UE25CS243A Computer Networks Mini-Project

Topological Setup:
- 1 OpenFlow 1.3 switch (s1)
- 4 Hosts (h1: Normal, h2: Attacker, h3: Legitimate, h4: TCP Server)
"""

from mininet.topo import Topo
import config


class DynamicBlockingTopology(Topo):
    """
    Mininet topology with one OpenFlow 1.3 switch and four hosts.
    Configured according to project specifications.
    """
    def build(self):
        # Add single OpenFlow 1.3 switch
        switch = self.addSwitch('s1', protocols=config.OF_VERSION)

        # Add hosts with static IP and MAC configurations from config.py
        for hostname, cfg in config.HOSTS_CONFIG.items():
            host = self.addHost(
                hostname,
                ip=cfg['ip'],
                mac=cfg['mac']
            )
            # Add link between host and switch
            # 100 Mbps link with 1ms delay for realistic LAN simulation
            self.addLink(host, switch, bw=100, delay='1ms')


# Enable running directly via `mn --custom topology.py --topo dhbtopo`
topos = {
    'dhbtopo': DynamicBlockingTopology
}

if __name__ == '__main__':
    from mininet.net import Mininet
    from mininet.node import RemoteController, OVSSwitch
    from mininet.cli import CLI
    from mininet.log import setLogLevel

    setLogLevel('info')
    topo = DynamicBlockingTopology()
    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        controller=RemoteController('c0', port=config.CONTROLLER_PORT),
        autoSetMacs=True
    )
    net.start()
    print("\n[INFO] Mininet topology started. Type 'exit' to quit.")
    CLI(net)
    net.stop()

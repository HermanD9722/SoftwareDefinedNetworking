#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Mininet topology for Buildings A and B with a core-to-core trunk.
# One L2 domain per VLAN across both buildings (management/office/guest).
#
# VLANs (shared across A and B):
#   management (vid 10):  10.0.10.0/28   GW 10.0.10.14
#   office     (vid 100): 10.0.100.0/23  GW 10.0.100.254
#   guest      (vid 200): 10.0.200.0/23  GW 10.0.200.254
#
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI
import argparse
import os

def set_host_net(host, ipv4=None, gw4=None, ipv6=None, gw6=None):
    """Configure host IPs and default routes."""
    host.cmd("ip addr flush dev %s" % host.defaultIntf())
    host.cmd("ip -6 addr flush dev %s" % host.defaultIntf())
    if ipv4:
        host.cmd("ip addr add %s dev %s" % (ipv4, host.defaultIntf()))
    if ipv6:
        host.cmd("ip -6 addr add %s dev %s" % (ipv6, host.defaultIntf()))
    host.cmd("ip link set %s up" % host.defaultIntf())
    if gw4:
        host.cmd("ip route replace default via %s" % gw4)
    if gw6:
        host.cmd("ip -6 route replace default via %s" % gw6)

def main():
    parser = argparse.ArgumentParser(description="Mininet topo for Faucet config (Buildings A and B, L2 VLANs across cores)")
    parser.add_argument("--c_ip", default="127.0.0.1", help="Faucet controller IP")
    parser.add_argument("--c_port", type=int, default=6653, help="Faucet controller TCP port")
    parser.add_argument("--openflow", default="OpenFlow13", help="OpenFlow protocol version for OVS")
    args = parser.parse_args()

    setLogLevel("info")

    net = Mininet(controller=None, switch=OVSKernelSwitch, link=TCLink, autoSetMacs=False, cleanup=True)

    info("*** Adding controller (Faucet)\n")
    c0 = net.addController("c0", controller=RemoteController, ip=args.c_ip, port=args.c_port)

    # =========================
    # Gebouw A
    # =========================
    info("*** Adding switches (Building A)\n")
    Asw1 = net.addSwitch("Asw1", dpid="0000000000000001", protocols=args.openflow, failMode="secure")  # begane grond
    Asw2 = net.addSwitch("Asw2", dpid="0000000000000002", protocols=args.openflow, failMode="secure")  # 1e verd.
    Asw3 = net.addSwitch("Asw3", dpid="0000000000000003", protocols=args.openflow, failMode="secure")  # 2e verd.
    Acore = net.addSwitch("Acore", dpid="0000000000000004", protocols=args.openflow, failMode="secure")# core/router A

    info("*** Adding hosts (Building A)\n")
    # Office A + mgmt
    Af1h1 = net.addHost("Af1h1"); Af1h2 = net.addHost("Af1h2"); 
    Af2h1 = net.addHost("Af2h1"); Af2h2 = net.addHost("Af2h2"); 
    Af3h1 = net.addHost("Af3h1"); Af3h2 = net.addHost("Af3h2"); 
    
    #management hosts met vaste MACs voor Ethernet port security
    Asvc1       = net.addHost("Asvc1",       mac="02:42:0a:00:0a:01")
    Asvc2       = net.addHost("Asvc2",       mac="02:42:0a:00:0a:02")
    Asvc3       = net.addHost("Asvc3",       mac="02:42:0a:00:0a:03")
    Acore_mgmt  = net.addHost("Acore_mgmt",  mac="02:42:0a:00:0a:04") 
    

    # Guest A
    Af1g1 = net.addHost("Af1g1"); Af1g2 = net.addHost("Af1g2")
    Af2g1 = net.addHost("Af2g1"); Af2g2 = net.addHost("Af2g2")
    Af3g1 = net.addHost("Af3g1"); Af3g2 = net.addHost("Af3g2")

    info("*** Creating links (Building A)\n")
    # Asw1 (begane grond)
    net.addLink(Af1h1, Asw1, port2=1)
    net.addLink(Af1h2, Asw1, port2=2)
    net.addLink(Af1g1, Asw1, port2=3)
    net.addLink(Asvc1, Asw1, port2=4)
    net.addLink(Af1g2, Asw1, port2=6)
    net.addLink(Acore_mgmt, Acore, port2=10)  # mgmt host naar core (management VLAN access)

    # Asw2 (1e verdieping)
    net.addLink(Af2h1, Asw2, port2=1)
    net.addLink(Af2h2, Asw2, port2=2)
    net.addLink(Af2g1, Asw2, port2=3)
    net.addLink(Asvc2, Asw2, port2=4)
    net.addLink(Af2g2, Asw2, port2=6)

    # Asw3 (2e verdieping)
    net.addLink(Af3h1, Asw3, port2=1)
    net.addLink(Af3h2, Asw3, port2=2)
    net.addLink(Af3g1, Asw3, port2=3)
    net.addLink(Asvc3, Asw3, port2=4)
    net.addLink(Af3g2, Asw3, port2=6)

    # Trunks A: access-switches -> Acore
    net.addLink(Asw1, Acore, port1=7,  port2=1)   # trunk alle VLANs
    net.addLink(Asw2, Acore, port1=23, port2=2)   # trunk alle VLANs
    net.addLink(Asw3, Acore, port1=24, port2=3)   # trunk alle VLANs

    # =========================
    # Gebouw B (mirror van A)
    # =========================
    info("*** Adding switches (Building B)\n")
    Bsw1 = net.addSwitch("Bsw1", dpid="0000000000000005", protocols=args.openflow, failMode="secure")
    Bsw2 = net.addSwitch("Bsw2", dpid="0000000000000006", protocols=args.openflow, failMode="secure")
    Bsw3 = net.addSwitch("Bsw3", dpid="0000000000000007", protocols=args.openflow, failMode="secure")
    Bcore = net.addSwitch("Bcore", dpid="0000000000000008", protocols=args.openflow, failMode="secure")

    info("*** Adding hosts (Building B)\n")
    # Office B
    Bf1h1 = net.addHost("Bf1h1"); Bf1h2 = net.addHost("Bf1h2");  
    Bf2h1 = net.addHost("Bf2h1"); Bf2h2 = net.addHost("Bf2h2"); 
    Bf3h1 = net.addHost("Bf3h1"); Bf3h2 = net.addHost("Bf3h2"); 

    #management hosts met vaste MACs voor Ethernet port security
    Bsvc1       = net.addHost("Bsvc1",       mac="02:42:0a:00:0b:01")
    Bsvc2       = net.addHost("Bsvc2",       mac="02:42:0a:00:0b:02")
    Bsvc3       = net.addHost("Bsvc3",       mac="02:42:0a:00:0b:03")
    Bcore_mgmt  = net.addHost("Bcore_mgmt",  mac="02:42:0a:00:0b:04")

    # Guest B
    Bf1g1 = net.addHost("Bf1g1"); Bf1g2 = net.addHost("Bf1g2")
    Bf2g1 = net.addHost("Bf2g1"); Bf2g2 = net.addHost("Bf2g2")
    Bf3g1 = net.addHost("Bf3g1"); Bf3g2 = net.addHost("Bf3g2")

    info("*** Creating links (Building B)\n")
    # Bsw1 (begane grond)
    net.addLink(Bf1h1, Bsw1, port2=1)
    net.addLink(Bf1h2, Bsw1, port2=2)
    net.addLink(Bf1g1, Bsw1, port2=3)
    net.addLink(Bsvc1, Bsw1, port2=4)
    net.addLink(Bf1g2, Bsw1, port2=6)
    net.addLink(Bcore_mgmt, Bcore, port2=10)  # mgmt host naar core (management VLAN access)

    # Bsw2 (1e verdieping)
    net.addLink(Bf2h1, Bsw2, port2=1)
    net.addLink(Bf2h2, Bsw2, port2=2)
    net.addLink(Bf2g1, Bsw2, port2=3)
    net.addLink(Bsvc2, Bsw2, port2=4)
    net.addLink(Bf2g2, Bsw2, port2=6)

    # Bsw3 (2e verdieping)
    net.addLink(Bf3h1, Bsw3, port2=1)
    net.addLink(Bf3h2, Bsw3, port2=2)
    net.addLink(Bf3g1, Bsw3, port2=3)
    net.addLink(Bsvc3, Bsw3, port2=4)
    net.addLink(Bf3g2, Bsw3, port2=6)

    # Trunks B: access-switches -> Bcore
    net.addLink(Bsw1, Bcore, port1=7,  port2=1)   # trunk alle VLANs
    net.addLink(Bsw2, Bcore, port1=23, port2=2)   # trunk alle VLANs
    net.addLink(Bsw3, Bcore, port1=24, port2=3)   # trunk alle VLANs

    # =========================
    # Core-to-core trunk (A <-> B) met alle VLANs getagd
    # =========================
    net.addLink(Acore, Bcore, port1=5, port2=5)

    info("*** Starting network\n")
    net.build()
    c0.start()

    # Start alle switches
    for sw in (Asw1, Asw2, Asw3, Acore, Bsw1, Bsw2, Bsw3, Bcore):
        sw.start([c0])
    # Zorg dat OVS OpenFlow versie goed staat
    for sw in (Asw1, Asw2, Asw3, Acore, Bsw1, Bsw2, Bsw3, Bcore):
        os.system(f"ovs-vsctl set Bridge {sw.name} protocols={args.openflow}")

    info("*** Configuring host IP addresses and default routes (Building A)\n")
    # Management A (10.0.10.0/28 via 10.0.10.14)
    set_host_net(Asvc1,      ipv4="10.0.10.1/28",  gw4="10.0.10.14",  ipv6="2001:10::11/64",  gw6="2001:10::1")
    set_host_net(Asvc2,      ipv4="10.0.10.2/28",  gw4="10.0.10.14",  ipv6="2001:10::12/64",  gw6="2001:10::1")
    set_host_net(Asvc3,      ipv4="10.0.10.3/28",  gw4="10.0.10.14",  ipv6="2001:10::13/64",  gw6="2001:10::1")
    set_host_net(Acore_mgmt, ipv4="10.0.10.5/28",  gw4="10.0.10.14",  ipv6="2001:10::20/64",  gw6="2001:10::1")

    # Office A (10.0.100.0/23 via 10.0.100.254)
    set_host_net(Af1h1, ipv4="10.0.100.10/23", gw4="10.0.100.254", ipv6="2001:100::10/64", gw6="2001:100::1")
    set_host_net(Af1h2, ipv4="10.0.100.11/23", gw4="10.0.100.254", ipv6="2001:100::11/64", gw6="2001:100::1")
    set_host_net(Af2h1, ipv4="10.0.100.12/23", gw4="10.0.100.254", ipv6="2001:100::12/64", gw6="2001:100::1")
    set_host_net(Af2h2, ipv4="10.0.100.13/23", gw4="10.0.100.254", ipv6="2001:100::13/64", gw6="2001:100::1")
    set_host_net(Af3h1, ipv4="10.0.100.14/23", gw4="10.0.100.254", ipv6="2001:100::14/64", gw6="2001:100::1")
    set_host_net(Af3h2, ipv4="10.0.100.15/23", gw4="10.0.100.254", ipv6="2001:100::15/64", gw6="2001:100::1")

    # Guest A (10.0.200.0/23 via 10.0.200.254)
    set_host_net(Af1g1, ipv4="10.0.200.10/23", gw4="10.0.200.254", ipv6="2001:200::10/64", gw6="2001:200::1")
    set_host_net(Af1g2, ipv4="10.0.200.11/23", gw4="10.0.200.254", ipv6="2001:200::11/64", gw6="2001:200::1")
    set_host_net(Af2g1, ipv4="10.0.200.12/23", gw4="10.0.200.254", ipv6="2001:200::12/64", gw6="2001:200::1")
    set_host_net(Af2g2, ipv4="10.0.200.13/23", gw4="10.0.200.254", ipv6="2001:200::13/64", gw6="2001:200::1")
    set_host_net(Af3g1, ipv4="10.0.200.14/23", gw4="10.0.200.254", ipv6="2001:200::14/64", gw6="2001:200::1")
    set_host_net(Af3g2, ipv4="10.0.200.15/23", gw4="10.0.200.254", ipv6="2001:200::15/64", gw6="2001:200::1")

    info("*** Configuring host IP addresses and default routes (Building B)\n")
    # Management B (zelfde /28, unieke hosts)
    set_host_net(Bsvc1,      ipv4="10.0.10.6/28",  gw4="10.0.10.14",  ipv6="2001:10::16/64",  gw6="2001:10::1")
    set_host_net(Bsvc2,      ipv4="10.0.10.7/28",  gw4="10.0.10.14",  ipv6="2001:10::17/64",  gw6="2001:10::1")
    set_host_net(Bsvc3,      ipv4="10.0.10.8/28",  gw4="10.0.10.14",  ipv6="2001:10::18/64",  gw6="2001:10::1")
    set_host_net(Bcore_mgmt, ipv4="10.0.10.9/28",  gw4="10.0.10.14",  ipv6="2001:10::21/64",  gw6="2001:10::1")

    # Office B (zelfde /23, unieke hosts)
    set_host_net(Bf1h1, ipv4="10.0.100.20/23", gw4="10.0.100.254", ipv6="2001:100::20/64", gw6="2001:100::1")
    set_host_net(Bf1h2, ipv4="10.0.100.21/23", gw4="10.0.100.254", ipv6="2001:100::21/64", gw6="2001:100::1")
    set_host_net(Bf2h1, ipv4="10.0.100.22/23", gw4="10.0.100.254", ipv6="2001:100::22/64", gw6="2001:100::1")
    set_host_net(Bf2h2, ipv4="10.0.100.23/23", gw4="10.0.100.254", ipv6="2001:100::23/64", gw6="2001:100::1")
    set_host_net(Bf3h1, ipv4="10.0.100.24/23", gw4="10.0.100.254", ipv6="2001:100::24/64", gw6="2001:100::1")
    set_host_net(Bf3h2, ipv4="10.0.100.25/23", gw4="10.0.100.254", ipv6="2001:100::25/64", gw6="2001:100::1")

    # Guest B (zelfde /23, unieke hosts)
    set_host_net(Bf1g1, ipv4="10.0.200.20/23", gw4="10.0.200.254", ipv6="2001:200::20/64", gw6="2001:200::1")
    set_host_net(Bf1g2, ipv4="10.0.200.21/23", gw4="10.0.200.254", ipv6="2001:200::21/64", gw6="2001:200::1")
    set_host_net(Bf2g1, ipv4="10.0.200.22/23", gw4="10.0.200.254", ipv6="2001:200::22/64", gw6="2001:200::1")
    set_host_net(Bf2g2, ipv4="10.0.200.23/23", gw4="10.0.200.254", ipv6="2001:200::23/64", gw6="2001:200::1")
    set_host_net(Bf3g1, ipv4="10.0.200.24/23", gw4="10.0.200.254", ipv6="2001:200::24/64", gw6="2001:200::1")
    set_host_net(Bf3g2, ipv4="10.0.200.25/23", gw4="10.0.200.254", ipv6="2001:200::25/64", gw6="2001:200::1")

    info("*** Topology is up. Use the CLI to test connectivity.\n")
    info("*** Examples:\n")
    info("    mininet> pingall\n")
    info("    mininet> Bf1h1 ping -c3 Af3h2         # office B ↔ office A (VLAN 100 over core-core trunk)\n")
    info("    mininet> Bf2g1 ping -c3 Af1g2         # guest B ↔ guest A (VLAN 200)\n")
    info("    mininet> Bsvc2 ping -c3 Acore_mgmt    # management B ↔ A (VLAN 10)\n")
    info("    mininet> sh ovs-ofctl -O OpenFlow13 dump-ports Acore\n")
    info("    mininet> sh ovs-ofctl -O OpenFlow13 dump-ports Bcore\n")

    CLI(net)
    net.stop()

if __name__ == "__main__":
    main()

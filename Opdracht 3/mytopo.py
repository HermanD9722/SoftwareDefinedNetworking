#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI
import argparse
import os

def set_host_net(host, ipv4=None, gw4=None):
    """Configure host IPv4 + default route."""
    intf = host.defaultIntf()
    host.cmd(f"ip addr flush dev {intf}")
    if ipv4:
        host.cmd(f"ip addr add {ipv4} dev {intf}")
    host.cmd(f"ip link set {intf} up")
    # clear any old default first
    host.cmd("ip route del default || true")
    if gw4:
        host.cmd(f"ip route replace default via {gw4}")

def configure_host_ipv6(host, ipv6_addr, iface, gw6=None):
    """Geef host een IPv6-adres en optioneel een default IPv6-route."""
    host.cmd(f'ip -6 addr flush dev {iface}')
    host.cmd(f'ip -6 addr add {ipv6_addr} dev {iface}')
    host.cmd(f'ip link set {iface} up')
    if gw6:
        host.cmd('ip -6 route flush default || true')
        host.cmd(f'ip -6 route add default via {gw6} dev {iface}')
    # forwarding blijft standaard uit op gewone hosts (prima)

def configure_nat_and_isp(net):
    Anat = net.get('Anat')
    Bnat = net.get('Bnat')
    Isp  = net.get('Isp')

    # ---------- Anat ----------
    Anat.cmd('ip addr flush dev Anat-eth0')
    Anat.cmd('ip -6 addr flush dev Anat-eth0')
    Anat.cmd('ip addr add 10.0.200.2/24 dev Anat-eth0')
    Anat.cmd('ip -6 addr add fd00:1234:abcd:200::1/64 dev Anat-eth0')
    Anat.cmd('ip link set Anat-eth0 up')

    Anat.cmd('ip addr flush dev Anat-eth2')
    Anat.cmd('ip -6 addr flush dev Anat-eth2')
    Anat.cmd('ip addr add 10.0.100.2/24 dev Anat-eth2')
    Anat.cmd('ip -6 addr add fd00:1234:abcd:100::1/64 dev Anat-eth2')
    Anat.cmd('ip link set Anat-eth2 up')

    Anat.cmd('ip addr flush dev Anat-eth1')
    Anat.cmd('ip -6 addr flush dev Anat-eth1')
    Anat.cmd('ip addr add 203.0.113.2/28 dev Anat-eth1')
    Anat.cmd('ip -6 addr add fd00:1234:abcd:ffff::2/64 dev Anat-eth1')
    Anat.cmd('ip link set Anat-eth1 up')

    Anat.cmd('ip route replace default via 203.0.113.1 dev Anat-eth1')
    Anat.cmd('ip -6 route replace default via fd00:1234:abcd:ffff::1 dev Anat-eth1')

    # forwarding aan
    Anat.cmd('sysctl -w net.ipv4.ip_forward=1')
    Anat.cmd('sysctl -w net.ipv6.conf.all.forwarding=1')

    # IPv4 firewall/NAT (houden we wel stateful + MASQUERADE)
    Anat.cmd('iptables -F FORWARD')
    Anat.cmd('iptables -t nat -F')
    Anat.cmd('iptables -P FORWARD DROP')
    Anat.cmd('iptables -A FORWARD -i Anat-eth0 -o Anat-eth1 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT')
    Anat.cmd('iptables -A FORWARD -i Anat-eth2 -o Anat-eth1 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT')
    Anat.cmd('iptables -A FORWARD -i Anat-eth1 -o Anat-eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT')
    Anat.cmd('iptables -A FORWARD -i Anat-eth1 -o Anat-eth2 -m state --state ESTABLISHED,RELATED -j ACCEPT')
    Anat.cmd('iptables -t nat -A POSTROUTING -o Anat-eth1 -j MASQUERADE')

    # IPv6 firewall = VOLLEDIG OPEN FORWARD (lab-mode fix)
    Anat.cmd('ip6tables -F FORWARD')
    Anat.cmd('ip6tables -P FORWARD ACCEPT')

    # ---------- Bnat ----------
    Bnat.cmd('ip addr flush dev Bnat-eth0')
    Bnat.cmd('ip -6 addr flush dev Bnat-eth0')
    Bnat.cmd('ip addr add 10.0.201.2/24 dev Bnat-eth0')
    Bnat.cmd('ip -6 addr add fd00:1234:abcd:201::1/64 dev Bnat-eth0')
    Bnat.cmd('ip link set Bnat-eth0 up')

    Bnat.cmd('ip addr flush dev Bnat-eth2')
    Bnat.cmd('ip -6 addr flush dev Bnat-eth2')
    Bnat.cmd('ip addr add 10.0.101.2/24 dev Bnat-eth2')
    Bnat.cmd('ip -6 addr add fd00:1234:abcd:101::1/64 dev Bnat-eth2')
    Bnat.cmd('ip link set Bnat-eth2 up')

    Bnat.cmd('ip addr flush dev Bnat-eth1')
    Bnat.cmd('ip -6 addr flush dev Bnat-eth1')
    Bnat.cmd('ip addr add 203.0.113.3/28 dev Bnat-eth1')
    Bnat.cmd('ip -6 addr add fd00:1234:abcd:ffff::3/64 dev Bnat-eth1')
    Bnat.cmd('ip link set Bnat-eth1 up')

    Bnat.cmd('ip route replace default via 203.0.113.1 dev Bnat-eth1')
    Bnat.cmd('ip -6 route replace default via fd00:1234:abcd:ffff::1 dev Bnat-eth1')

    Bnat.cmd('sysctl -w net.ipv4.ip_forward=1')
    Bnat.cmd('sysctl -w net.ipv6.conf.all.forwarding=1')

    # IPv4 firewall/NAT voor Bnat
    Bnat.cmd('iptables -F FORWARD')
    Bnat.cmd('iptables -t nat -F')
    Bnat.cmd('iptables -P FORWARD DROP')
    Bnat.cmd('iptables -A FORWARD -i Bnat-eth0 -o Bnat-eth1 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT')
    Bnat.cmd('iptables -A FORWARD -i Bnat-eth2 -o Bnat-eth1 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT')
    Bnat.cmd('iptables -A FORWARD -i Bnat-eth1 -o Bnat-eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT')
    Bnat.cmd('iptables -A FORWARD -i Bnat-eth1 -o Bnat-eth2 -m state --state ESTABLISHED,RELATED -j ACCEPT')
    Bnat.cmd('iptables -t nat -A POSTROUTING -o Bnat-eth1 -j MASQUERADE')

    # IPv6 firewall volledig open voor Bnat
    Bnat.cmd('ip6tables -F FORWARD')
    Bnat.cmd('ip6tables -P FORWARD ACCEPT')

    # ---------- ISP ----------
    Isp.cmd('ip link add isp-br0 type bridge || true')
    Isp.cmd('ip link set isp-br0 up')

    Isp.cmd('ip link set Isp-eth0 master isp-br0')
    Isp.cmd('ip link set Isp-eth1 master isp-br0')
    Isp.cmd('ip link set Isp-eth0 up')
    Isp.cmd('ip link set Isp-eth1 up')

    Isp.cmd('ip addr flush dev Isp-eth0')
    Isp.cmd('ip addr flush dev Isp-eth1')
    Isp.cmd('ip -6 addr flush dev Isp-eth0')
    Isp.cmd('ip -6 addr flush dev Isp-eth1')
    Isp.cmd('ip addr flush dev isp-br0 || true')
    Isp.cmd('ip -6 addr flush dev isp-br0 || true')

    Isp.cmd('ip addr add 203.0.113.1/28 dev isp-br0')
    Isp.cmd('ip -6 addr add fd00:1234:abcd:ffff::1/64 dev isp-br0')

    Isp.cmd('sysctl -w net.ipv4.ip_forward=1')
    Isp.cmd('sysctl -w net.ipv6.conf.all.forwarding=1')

    Isp.cmd('ip route replace 10.0.100.0/24 via 203.0.113.2 dev isp-br0')
    Isp.cmd('ip route replace 10.0.200.0/24 via 203.0.113.2 dev isp-br0')
    Isp.cmd('ip route replace 10.0.101.0/24 via 203.0.113.3 dev isp-br0')
    Isp.cmd('ip route replace 10.0.201.0/24 via 203.0.113.3 dev isp-br0')

    Isp.cmd('ip -6 route replace fd00:1234:abcd:100::/64 via fd00:1234:abcd:ffff::2 dev isp-br0')
    Isp.cmd('ip -6 route replace fd00:1234:abcd:200::/64 via fd00:1234:abcd:ffff::2 dev isp-br0')
    Isp.cmd('ip -6 route replace fd00:1234:abcd:101::/64 via fd00:1234:abcd:ffff::3 dev isp-br0')
    Isp.cmd('ip -6 route replace fd00:1234:abcd:201::/64 via fd00:1234:abcd:ffff::3 dev isp-br0')



def configure_hosts_ipv6(net):
    """Geef een representatieve set hosts IPv6 + default gw6."""
    # Office A
    configure_host_ipv6(
        net.get('Af1h1'),
        ipv6_addr='fd00:1234:abcd:100::10/64',
        iface='Af1h1-eth0',
        gw6='fd00:1234:abcd:100::1'
    )
    configure_host_ipv6(
        net.get('Af1h2'),
        ipv6_addr='fd00:1234:abcd:100::11/64',
        iface='Af1h2-eth0',
        gw6='fd00:1234:abcd:100::1'
    )

    # Guest A
    configure_host_ipv6(
        net.get('Af1g1'),
        ipv6_addr='fd00:1234:abcd:200::10/64',
        iface='Af1g1-eth0',
        gw6='fd00:1234:abcd:200::1'
    )
    configure_host_ipv6(
        net.get('Af1g2'),
        ipv6_addr='fd00:1234:abcd:200::11/64',
        iface='Af1g2-eth0',
        gw6='fd00:1234:abcd:200::1'
    )

    # Office B
    configure_host_ipv6(
        net.get('Bf1h1'),
        ipv6_addr='fd00:1234:abcd:101::10/64',
        iface='Bf1h1-eth0',
        gw6='fd00:1234:abcd:101::1'
    )

    # Guest B
    configure_host_ipv6(
        net.get('Bf1g1'),
        ipv6_addr='fd00:1234:abcd:201::10/64',
        iface='Bf1g1-eth0',
        gw6='fd00:1234:abcd:201::1'
    )

    # Mgmt (geen default gw6)
    configure_host_ipv6(
        net.get('Asvc1'),
        ipv6_addr='fd00:1234:abcd:10::11/64',
        iface='Asvc1-eth0',
        gw6=None
    )
    configure_host_ipv6(
        net.get('Bsvc1'),
        ipv6_addr='fd00:1234:abcd:10::21/64',
        iface='Bsvc1-eth0',
        gw6=None
    )

def main():
    parser = argparse.ArgumentParser(
        description="Two-building campus with per-building NAT and shared mgmt VLAN, Faucet 1.10.11 style (L2+ACL only)."
    )
    parser.add_argument("--c_ip", default="127.0.0.1", help="Faucet controller IP")
    parser.add_argument("--c_port", type=int, default=6653, help="Faucet controller TCP port")
    parser.add_argument("--openflow", default="OpenFlow13", help="OpenFlow protocol version")
    args = parser.parse_args()

    setLogLevel("info")

    net = Mininet(controller=None,
                  switch=OVSKernelSwitch,
                  link=TCLink,
                  autoSetMacs=False,
                  autoStaticArp=True)

    info("*** Add Faucet controller\n")
    c0 = net.addController("c0", controller=RemoteController, ip=args.c_ip, port=args.c_port)

    info("*** Add switches (Building A)\n")
    Asw1 = net.addSwitch("Asw1", dpid="0000000000000001", protocols=args.openflow, failMode="secure")
    Asw2 = net.addSwitch("Asw2", dpid="0000000000000002", protocols=args.openflow, failMode="secure")
    Asw3 = net.addSwitch("Asw3", dpid="0000000000000003", protocols=args.openflow, failMode="secure")
    Acore = net.addSwitch("Acore", dpid="0000000000000004", protocols=args.openflow, failMode="secure")

    info("*** Add switches (Building B)\n")
    Bsw1 = net.addSwitch("Bsw1", dpid="0000000000000005", protocols=args.openflow, failMode="secure")
    Bsw2 = net.addSwitch("Bsw2", dpid="0000000000000006", protocols=args.openflow, failMode="secure")
    Bsw3 = net.addSwitch("Bsw3", dpid="0000000000000007", protocols=args.openflow, failMode="secure")
    Bcore = net.addSwitch("Bcore", dpid="0000000000000008", protocols=args.openflow, failMode="secure")

    info("*** Add hosts Building A (office, guest, mgmt)\n")
    # Office A
    Af1h1 = net.addHost("Af1h1")
    Af1h2 = net.addHost("Af1h2")
    Af2h1 = net.addHost("Af2h1")
    Af2h2 = net.addHost("Af2h2")
    Af3h1 = net.addHost("Af3h1")
    Af3h2 = net.addHost("Af3h2")

    # Guest A
    Af1g1 = net.addHost("Af1g1")
    Af1g2 = net.addHost("Af1g2")
    Af2g1 = net.addHost("Af2g1")
    Af2g2 = net.addHost("Af2g2")
    Af3g1 = net.addHost("Af3g1")
    Af3g2 = net.addHost("Af3g2")

    # Mgmt A
    Asvc1      = net.addHost("Asvc1",      mac="02:42:0a:00:0a:01")
    Asvc2      = net.addHost("Asvc2",      mac="02:42:0a:00:0a:02")
    Asvc3      = net.addHost("Asvc3",      mac="02:42:0a:00:0a:03")
    Acore_mgmt = net.addHost("Acore_mgmt", mac="02:42:0a:00:0a:04")

    info("*** Add hosts Building B (office, guest, mgmt)\n")
    # Office B
    Bf1h1 = net.addHost("Bf1h1")
    Bf1h2 = net.addHost("Bf1h2")
    Bf2h1 = net.addHost("Bf2h1")
    Bf2h2 = net.addHost("Bf2h2")
    Bf3h1 = net.addHost("Bf3h1")
    Bf3h2 = net.addHost("Bf3h2")

    # Guest B
    Bf1g1 = net.addHost("Bf1g1")
    Bf1g2 = net.addHost("Bf1g2")
    Bf2g1 = net.addHost("Bf2g1")
    Bf2g2 = net.addHost("Bf2g2")
    Bf3g1 = net.addHost("Bf3g1")
    Bf3g2 = net.addHost("Bf3g2")

    # Mgmt B
    Bsvc1      = net.addHost("Bsvc1",      mac="02:42:0a:00:0b:01")
    Bsvc2      = net.addHost("Bsvc2",      mac="02:42:0a:00:0b:02")
    Bsvc3      = net.addHost("Bsvc3",      mac="02:42:0a:00:0b:03")
    Bcore_mgmt = net.addHost("Bcore_mgmt", mac="02:42:0a:00:0b:04")

    info("*** Add NAT/ISP nodes\n")
    Anat = net.addHost("Anat")
    Bnat = net.addHost("Bnat")
    Isp  = net.addHost("Isp")

    info("*** Wire Building A access -> users\n")
    # Floor 1
    net.addLink(Af1h1, Asw1, port2=1)
    net.addLink(Af1h2, Asw1, port2=2)
    net.addLink(Af1g1, Asw1, port2=3)
    net.addLink(Asvc1, Asw1, port2=4)
    net.addLink(Af1g2, Asw1, port2=6)
    # Floor 2
    net.addLink(Af2h1, Asw2, port2=1)
    net.addLink(Af2h2, Asw2, port2=2)
    net.addLink(Af2g1, Asw2, port2=3)
    net.addLink(Asvc2, Asw2, port2=4)
    net.addLink(Af2g2, Asw2, port2=6)
    # Floor 3
    net.addLink(Af3h1, Asw3, port2=1)
    net.addLink(Af3h2, Asw3, port2=2)
    net.addLink(Af3g1, Asw3, port2=3)
    net.addLink(Asvc3, Asw3, port2=4)
    net.addLink(Af3g2, Asw3, port2=6)

    info("*** Wire Building B access -> users\n")
    net.addLink(Bf1h1, Bsw1, port2=1)
    net.addLink(Bf1h2, Bsw1, port2=2)
    net.addLink(Bf1g1, Bsw1, port2=3)
    net.addLink(Bsvc1, Bsw1, port2=4)
    net.addLink(Bf1g2, Bsw1, port2=6)

    net.addLink(Bf2h1, Bsw2, port2=1)
    net.addLink(Bf2h2, Bsw2, port2=2)
    net.addLink(Bf2g1, Bsw2, port2=3)
    net.addLink(Bsvc2, Bsw2, port2=4)
    net.addLink(Bf2g2, Bsw2, port2=6)

    net.addLink(Bf3h1, Bsw3, port2=1)
    net.addLink(Bf3h2, Bsw3, port2=2)
    net.addLink(Bf3g1, Bsw3, port2=3)
    net.addLink(Bsvc3, Bsw3, port2=4)
    net.addLink(Bf3g2, Bsw3, port2=6)

    info("*** Uplinks access -> core\n")
    # Building A uplinks
    net.addLink(Asw1, Acore, port1=7,  port2=1)
    net.addLink(Asw2, Acore, port1=23, port2=2)
    net.addLink(Asw3, Acore, port1=24, port2=3)
    # Building B uplinks
    net.addLink(Bsw1, Bcore, port1=7,  port2=1)
    net.addLink(Bsw2, Bcore, port1=23, port2=2)
    net.addLink(Bsw3, Bcore, port1=24, port2=3)

    info("*** Core-to-core trunk (shared mgmt VLAN)\n")
    net.addLink(Acore, Bcore, port1=5, port2=5)

    info("*** Connect NATs to cores\n")
    # Building A NAT to Acore:
    net.addLink(Anat, Acore, intfName1='Anat-eth0', port2=6)  # guest_a
    net.addLink(Anat, Acore, intfName1='Anat-eth2', port2=7)  # office_a

    # Building B NAT to Bcore:
    net.addLink(Bnat, Bcore, intfName1='Bnat-eth0', port2=6)  # guest_b
    net.addLink(Bnat, Bcore, intfName1='Bnat-eth2', port2=7)  # office_b

    info("*** Connect NATs to ISP (WAN /28)\n")
    net.addLink(Anat, Isp, intfName1='Anat-eth1', port2=0)
    net.addLink(Bnat, Isp, intfName1='Bnat-eth1', port2=1)

    info("*** Mgmt hosts into core (native mgmt VLAN ports)\n")
    net.addLink(Acore_mgmt, Acore, port2=10)
    net.addLink(Bcore_mgmt, Bcore, port2=10)

    info("*** Build network\n")
    net.build()
    c0.start()

    # Koppel OVS aan Faucet
    for swname in ("Asw1","Asw2","Asw3","Acore","Bsw1","Bsw2","Bsw3","Bcore"):
        sw = net.get(swname)
        sw.start([c0])
        os.system(f"ovs-vsctl set Bridge {swname} protocols={args.openflow}")

    info("*** Configure NAT/ISP (routers + ISP first)\n")
    configure_nat_and_isp(net)

    info("*** Assign IPv4 addresses to hosts\n")
    # Building A office
    set_host_net(Af1h1, ipv4="10.0.100.10/24", gw4="10.0.100.2")
    set_host_net(Af1h2, ipv4="10.0.100.11/24", gw4="10.0.100.2")
    set_host_net(Af2h1, ipv4="10.0.100.12/24", gw4="10.0.100.2")
    set_host_net(Af2h2, ipv4="10.0.100.13/24", gw4="10.0.100.2")
    set_host_net(Af3h1, ipv4="10.0.100.14/24", gw4="10.0.100.2")
    set_host_net(Af3h2, ipv4="10.0.100.15/24", gw4="10.0.100.2")

    # Building A guest
    set_host_net(Af1g1, ipv4="10.0.200.10/24", gw4="10.0.200.2")
    set_host_net(Af1g2, ipv4="10.0.200.11/24", gw4="10.0.200.2")
    set_host_net(Af2g1, ipv4="10.0.200.12/24", gw4="10.0.200.2")
    set_host_net(Af2g2, ipv4="10.0.200.13/24", gw4="10.0.200.2")
    set_host_net(Af3g1, ipv4="10.0.200.14/24", gw4="10.0.200.2")
    set_host_net(Af3g2, ipv4="10.0.200.15/24", gw4="10.0.200.2")

    # Building B office
    set_host_net(Bf1h1, ipv4="10.0.101.10/24", gw4="10.0.101.2")
    set_host_net(Bf1h2, ipv4="10.0.101.11/24", gw4="10.0.101.2")
    set_host_net(Bf2h1, ipv4="10.0.101.12/24", gw4="10.0.101.2")
    set_host_net(Bf2h2, ipv4="10.0.101.13/24", gw4="10.0.101.2")
    set_host_net(Bf3h1, ipv4="10.0.101.14/24", gw4="10.0.101.2")
    set_host_net(Bf3h2, ipv4="10.0.101.15/24", gw4="10.0.101.2")

    # Building B guest
    set_host_net(Bf1g1, ipv4="10.0.201.10/24", gw4="10.0.201.2")
    set_host_net(Bf1g2, ipv4="10.0.201.11/24", gw4="10.0.201.2")
    set_host_net(Bf2g1, ipv4="10.0.201.12/24", gw4="10.0.201.2")
    set_host_net(Bf2g2, ipv4="10.0.201.13/24", gw4="10.0.201.2")
    set_host_net(Bf3g1, ipv4="10.0.201.14/24", gw4="10.0.201.2")
    set_host_net(Bf3g2, ipv4="10.0.201.15/24", gw4="10.0.201.2")

    # Mgmt shared
    set_host_net(Asvc1,      ipv4="10.0.10.1/28")
    set_host_net(Asvc2,      ipv4="10.0.10.2/28")
    set_host_net(Asvc3,      ipv4="10.0.10.3/28")
    set_host_net(Acore_mgmt, ipv4="10.0.10.4/28")

    set_host_net(Bsvc1,      ipv4="10.0.10.5/28")
    set_host_net(Bsvc2,      ipv4="10.0.10.6/28")
    set_host_net(Bsvc3,      ipv4="10.0.10.7/28")
    set_host_net(Bcore_mgmt, ipv4="10.0.10.8/28")

    info("*** Configure IPv6 addresses + default routes on hosts (after NAT/ISP is live)\n")
    configure_hosts_ipv6(net)

    # --- final IPv6 warmup so first client ping6 works ---
    Anat = net.get('Anat')
    Bnat = net.get('Bnat')

    # kleine pauze zodat OVS + bridge echt up zijn
    Anat.cmd('sleep 0.2')
    Bnat.cmd('sleep 0.2')

    # forceer ND naar ISP vanaf beide NAT-routers
    Anat.cmd('ping6 -c1 -W 1 fd00:1234:abcd:ffff::1 || true')
    Bnat.cmd('ping6 -c1 -W 1 fd00:1234:abcd:ffff::1 || true')


    info("*** Ready. Suggested tests:\n")
    info("  Af1h1 ping -c3 203.0.113.1\n")
    info("  Af1h1 ping6 -c3 fd00:1234:abcd:ffff::1\n")
    info("  Af1g1 ping6 -c3 fd00:1234:abcd:ffff::1\n")
    info("  Isp ping6 -c3 fd00:1234:abcd:100::10 (zou nu moeten werken omdat IPv6 FORWARD op ACCEPT staat)\n")

    CLI(net)
    net.stop()


if __name__ == "__main__":
    main()

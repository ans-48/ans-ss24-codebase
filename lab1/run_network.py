#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from mininet.topo import Topo

class Lab1Topo(Topo):
    def build(self, **_opts):
        h1 = self.addHost('h1', ip='10.0.1.2/24', defaultRoute='via 10.0.1.1')
        h2 = self.addHost('h2', ip='10.0.1.3/24', defaultRoute='via 10.0.1.1')
        ser = self.addHost('ser', ip='10.0.2.2/24', defaultRoute='via 10.0.2.1')
        ext = self.addHost('ext', ip='192.168.1.123/24', defaultRoute='via 192.168.1.1')

        s1 = self.addSwitch('s1', dpid='0000000000000011')
        s2 = self.addSwitch('s2', dpid='0000000000000012')
        s3 = self.addSwitch('s3', dpid='0000000000000013')

        link_opts = {'bw': 15, 'delay': '10ms'}

        self.addLink(h1, s1, **link_opts)
        self.addLink(h2, s1, **link_opts)
        self.addLink(ser, s2, **link_opts)
        self.addLink(s1, s3, port1=3, port2=1, **link_opts)
        self.addLink(s2, s3, port1=2, port2=2, **link_opts)
        self.addLink(ext, s3, port1=1, port2=3, **link_opts)

def run_lab_network():
    info('* Starting network creation *\n')
    
    info('--- Defining Controller (Ryu expected at 127.0.0.1:6653)...\n')
    c1 = RemoteController(name='c1', ip='127.0.0.1', port=6653)

    lab_topo = Lab1Topo()

    info('--- Creating Mininet object with OVS switches and TC links...\n')
    net = Mininet(topo=lab_topo,
                  controller=c1,
                  switch=OVSKernelSwitch,
                  link=TCLink,
                  autoSetMacs=True,
                  autoStaticArp=False)

    info('* Building network simulation *\n')
    net.start() 

    info('* Running Mininet CLI (type "exit" to quit) *\n')
    CLI(net)

    info('* Stopping network simulation *\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_lab_network()

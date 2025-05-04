# File: run_network.py

#!/usr/bin/env python3
"""
run_network.py: Creates the network topology for Lab 1 using Mininet.
Based on the topology described in Figure 1 of ANS_SS25_Lab1.pdf.
"""

# Import necessary parts from the Mininet library
from mininet.net import Mininet                      # The main class for creating network topologies
from mininet.node import Controller, RemoteController, OVSKernelSwitch # Node types: Controller, External Controller, Open vSwitch
from mininet.cli import CLI                          # Command Line Interface for interacting with the network
from mininet.log import setLogLevel, info            # For printing informational messages
from mininet.link import TCLink                      # Link type that allows setting properties like bandwidth/delay

def create_network():
    """Creates and configures the Mininet network."""
    info('* Starting network creation *\n')

    # 1. Define the Controller
    # This tells Mininet that the controller (the "brain") is running outside
    # of Mininet itself. We specify its IP address and the port it listens on.
    # Ryu's default port is 6653 (even though the diagram shows 6633 sometimes).
    info('--- Defining Controller (Ryu expected at 127.0.0.1:6653)...\n')
    c1 = RemoteController( name='c1',        # Give the controller a name
                           ip='127.0.0.1',  # Standard localhost IP
                           port=6653 )      # Standard OpenFlow port Ryu uses

    # 2. Create the main Mininet Network object
    # We pass the controller object 'c1' to the network.
    # switch=OVSKernelSwitch: Use Open vSwitch (a software switch) for s1, s2, s3.
    # link=TCLink: Use links where we can set traffic control parameters (bw, delay).
    # autoSetMacs=True: Let Mininet assign unique MAC addresses to hosts.
    # autoStaticArp=False: Disable Mininet's automatic ARP table entries; our controller will handle ARP.
    info('--- Creating Mininet object with OVS switches and TC links...\n')
    net = Mininet( controller=c1,
                   switch=OVSKernelSwitch,
                   link=TCLink,
                   autoSetMacs=True,
                   autoStaticArp=False )

    # 3. Add Hosts (Virtual Computers)
    # net.addHost(name, ip, defaultRoute) creates each host.
    # The IP address includes the subnet mask length (/24).
    # defaultRoute tells the host where to send packets destined for other networks.
    info('--- Adding Hosts (h1, h2, ser, ext)...\n')
    h1 = net.addHost('h1', ip='10.0.1.2/24', defaultRoute='via 10.0.1.1')
    h2 = net.addHost('h2', ip='10.0.1.3/24', defaultRoute='via 10.0.1.1')
    ser = net.addHost('ser', ip='10.0.2.2/24', defaultRoute='via 10.0.2.1')
    ext = net.addHost('ext', ip='192.168.1.123/24', defaultRoute='via 192.168.1.1')

    # 4. Add Switches (s1, s2) and the Router (s3)
    # net.addSwitch(name, dpid) creates the switches/router.
    # We treat s3 as a switch here; the controller makes it act like a router.
    # dpid (Datapath ID) is a unique hexadecimal identifier for the controller.
    info('--- Adding Switches (s1, s2) and Router (s3)...\n')
    s1 = net.addSwitch('s1', dpid='0000000000000011') # Use simple DPIDs
    s2 = net.addSwitch('s2', dpid='0000000000000012')
    s3 = net.addSwitch('s3', dpid='0000000000000013') # The router device

    # 5. Create Links (Virtual Cables)
    # net.addLink(node1, node2, port1, port2, **options) connects the devices.
    # link_opts defines bandwidth (bw) and delay based on the PDF.
    # Specifying port numbers (e.g., port1=3, port2=1) helps map the physical
    # connections to the logical port numbers used in the controller (ROUTER_PORTS).
    info('--- Creating Links with specified BW and Delay...\n')
    link_opts = {'bw': 15, 'delay': '10ms'} # 15 Mbps bandwidth, 10ms delay

    # Connect h1 and h2 to switch s1 (Mininet auto-assigns s1 ports, likely 1 and 2)
    net.addLink(h1, s1, **link_opts)
    net.addLink(h2, s1, **link_opts)

    # Connect server ser to switch s2 (Mininet auto-assigns s2 port, likely 1)
    net.addLink(ser, s2, **link_opts)

    # Connect the switches and external host to the router (s3) using specific ports
    # Router Port 1 <-> Switch s1 (using s1's port 3, assumes ports 1,2 used for hosts)
    net.addLink(s1, s3, port1=3, port2=1, **link_opts)
    # Router Port 2 <-> Switch s2 (using s2's port 2, assumes port 1 used for server)
    net.addLink(s2, s3, port1=2, port2=2, **link_opts)
    # Router Port 3 <-> External host ext (using ext's port 1, assumed)
    net.addLink(ext, s3, port1=1, port2=3, **link_opts)

    # 6. Start the Network
    # net.build() creates the network objects based on the definitions above.
    info('* Building network simulation *\n')
    net.build()

    # Start the controller first (although it's external, this ensures Mininet knows about it)
    # info('--- Starting controller connection process ---\n')
    # c1.start() # Often not needed explicitly for RemoteController

    # Start the switches/router, making them connect to the controller 'c1'
    info('--- Starting switches and router (s1, s2, s3) ---\n')
    net.get('s1').start([c1])
    net.get('s2').start([c1])
    net.get('s3').start([c1])

    # Note: The actual gateway IPs (10.0.1.1, 10.0.2.1, 192.168.1.1) are logical
    # addresses managed by the Ryu controller. They are NOT assigned directly to
    # the 's3' switch's interfaces within Mininet itself. Hosts just use them
    # as their 'defaultRoute'.

    # 7. Run the Command Line Interface (CLI)
    # This provides the 'mininet>' prompt for interaction (ping, iperf, etc.).
    info('* Running Mininet CLI (type "exit" to quit) *\n')
    CLI(net)

    # 8. Stop the Network
    # Cleans up the virtual interfaces and processes when CLI exits.
    info('* Stopping network simulation *\n')
    net.stop()

# Standard Python entry point check
if __name__ == '__main__':
    setLogLevel('info') # Set Mininet's logging level (info, debug, warning, etc.)
    create_network()    # Call the main function to build the network

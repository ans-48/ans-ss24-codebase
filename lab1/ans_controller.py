"""
 Copyright 2024 Computer Networks Group @ UPB

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 """

import ipaddress
from collections import defaultdict
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.ofproto import inet

class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Here you can initialize the data structures you want to keep at the controller
        self.mac_to_port = {}
        self.router_dpid = 3  # This must match the dpid used for s3
        self.port_to_own_mac = {
            1: "00:00:00:00:01:01",
            2: "00:00:00:00:01:02",
            3: "00:00:00:00:01:03"
        }
        self.port_to_own_ip = {
            1: "10.0.1.1",
            2: "10.0.2.1",
            3: "192.168.1.1"
        }
        self.arp_table = {}  # IP -> MAC
        self.packet_queue = {}  # IP -> list of (datapath, packet, in_port)
        self.arp_waiting_queue = defaultdict(list)
        self.routing_table = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # Handle the packet_in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        
        msg = ev.msg
        datapath = msg.datapath

        # Your controller implementation should start here
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP packets used for topology discovery
        if eth.ethertype == ether_types.ETH_TYPE_LLDP: return

        if datapath.id == self.router_dpid:
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt:
                self.handle_router_arp(datapath, in_port, eth, arp_pkt)
                return

            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt:
                icmp_pkt = pkt.get_protocol(icmp.icmp)
                if icmp_pkt and ip_pkt.dst in self.port_to_own_ip.values() and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                    self.handle_router_icmp(datapath, in_port, eth, ip_pkt, icmp_pkt)
                    return
                if not (ip_pkt.dst in self.port_to_own_ip.values() and ip_pkt.proto == inet.IPPROTO_ICMP):
                    self.handle_router_ip(datapath, in_port, pkt, eth, ip_pkt)
                    return

        self.handle_switch_packet(datapath, in_port, eth, msg)

    def handle_switch_packet(self, datapath, in_port, eth, msg):
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dst = eth.dst
        src = eth.src

        # Initialize per-switch MAC table if not present
        self.mac_to_port.setdefault(dpid, {})

        # Learn the source MAC on the input port
        self.mac_to_port[dpid][src] = in_port

        # Determine output port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD  # Flood if destination unknown

        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow only if the output is not flood
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(eth_dst=dst)
            self.add_flow(datapath, priority=1, match=match, actions=actions)

        # Send packet out (only needed if no buffer was used for add_flow)
        out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port,
                                      actions=actions,
                                      data=msg.data)
        datapath.send_msg(out)

    def handle_router_arp(self, datapath, in_port, eth, arp_pkt):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Handle ARP Request directed to router
        if arp_pkt.opcode == arp.ARP_REQUEST:
            for port, ip in self.port_to_own_ip.items():
                if arp_pkt.dst_ip == ip:
                    self.logger.info("Router responding to ARP request for %s", ip)

                    arp_reply = packet.Packet()
                    arp_reply.add_protocol(
                        ethernet.ethernet(
                            ethertype=eth.ethertype,
                            dst=eth.src,
                            src=self.port_to_own_mac[port]
                        )
                    )
                    arp_reply.add_protocol(
                        arp.arp(
                            opcode=arp.ARP_REPLY,
                            src_mac=self.port_to_own_mac[port],
                            src_ip=ip,
                            dst_mac=eth.src,
                            dst_ip=arp_pkt.src_ip
                        )
                    )
                    arp_reply.serialize()

                    actions = [parser.OFPActionOutput(in_port)]
                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=ofproto.OFPP_CONTROLLER,
                        actions=actions,
                        data=arp_reply.data
                    )
                    datapath.send_msg(out)
                    return

        # Handle ARP Reply - learn mapping and process queued packets
        elif arp_pkt.opcode == arp.ARP_REPLY:
            self.logger.info("Router learned ARP: %s is at %s", arp_pkt.src_ip, arp_pkt.src_mac)
            self.arp_table[arp_pkt.src_ip] = arp_pkt.src_mac

            arp_dst_ip = arp_pkt.dst_ip
            if arp_dst_ip in self.arp_waiting_queue:
                for queued in self.arp_waiting_queue[arp_dst_ip]:
                    q_datapath, q_pkt, q_in_port = queued
                    self.forward_ip_packet(q_datapath, q_pkt, q_in_port)
                del self.arp_waiting_queue[arp_dst_ip]

            if arp_pkt.src_ip in self.packet_queue:
                for queued_datapath, pkt_data, out_port in self.packet_queue[arp_pkt.src_ip]:
                    eth_hdr = pkt_data.get_protocol(ethernet.ethernet)
                    ip_pkt = pkt_data.get_protocol(ipv4.ipv4)
                    if not eth_hdr or not ip_pkt:
                        continue

                    # Send queued packet now that we know dest MAC
                    actions = [parser.OFPActionOutput(out_port)]
                    new_eth = ethernet.ethernet(
                        ethertype=eth_hdr.ethertype,
                        src=self.port_to_own_mac[out_port],
                        dst=arp_pkt.src_mac
                    )
                    pkt_data.protocols[0] = new_eth
                    pkt_data.serialize()

                    out = parser.OFPPacketOut(
                        datapath=queued_datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=ofproto.OFPP_CONTROLLER,
                        actions=actions,
                        data=pkt_data.data
                    )
                    datapath.send_msg(out)
                del self.packet_queue[arp_pkt.src_ip]

    def handle_router_icmp(self, datapath, in_port, eth, ip_pkt, icmp_pkt):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Find which port's IP matches the destination IP
        expected_ip = self.port_to_own_ip.get(in_port)
        expected_mac = self.port_to_own_mac.get(in_port)
        if ip_pkt.dst != expected_ip: return

        out_mac = expected_mac
        if not out_mac:
            return  # Shouldn't happen

        # Build ICMP Echo Reply
        echo_reply = packet.Packet()
        echo_reply.add_protocol(
            ethernet.ethernet(
                ethertype=eth.ethertype,
                src=out_mac,
                dst=eth.src
            )
        )
        echo_reply.add_protocol(
            ipv4.ipv4(
                dst=ip_pkt.src,
                src=ip_pkt.dst,
                proto=ip_pkt.proto
            )
        )
        echo_reply.add_protocol(
            icmp.icmp(
                type_=icmp.ICMP_ECHO_REPLY,
                code=0,
                csum=0,
                data=icmp_pkt.data
            )
        )

        echo_reply.serialize()

        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=echo_reply.data
        )
        datapath.send_msg(out)

    def handle_router_ip(self, datapath, in_port, pkt, eth_pkt, ip_pkt):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        dst_ip = ip_pkt.dst
        src_ip = ip_pkt.src
        src_mac = eth_pkt.src
        proto = ip_pkt.proto

        if ip_pkt.ttl <= 1: return

        # Access Control Logic
        is_ext = src_ip.startswith("192.168.1.")
        is_ser = src_ip == "10.0.2.2"
        is_ser_dst = dst_ip == "10.0.2.2"
        is_ext_dst = dst_ip.startswith("192.168.1.")

        # Drop if ext tries to reach any internal host
        if is_ext and not is_ext_dst:
            return

        # Drop if internal host tries to ping ext
        if is_ext_dst and proto == inet.IPPROTO_ICMP:
            return

        # Drop TCP/UDP from/to ext <-> ser
        if (is_ext and is_ser_dst or is_ser and is_ext_dst) and proto in (inet.IPPROTO_TCP, inet.IPPROTO_UDP):
            return

        # Learn source IP -> port, MAC
        self.routing_table[src_ip] = (in_port, src_mac)

        # Drop if destination is one of the router's own IPs (we already handle ICMP separately)
        if dst_ip in self.port_to_own_ip.values():
            return

        # Lookup destination in routing table
        if dst_ip not in self.routing_table:
            out_port = self.get_out_port_for_ip(dst_ip)
            if out_port is None:
                return  # Unknown destination subnet
            self.arp_waiting_queue[dst_ip].append((datapath, pkt, in_port))
            self.send_arp_request(datapath, out_port, self.port_to_own_mac[out_port],
                          self.port_to_own_ip[out_port], dst_ip)
            return

        out_port, dst_mac = self.routing_table[dst_ip]
        src_mac_for_out_port = self.port_to_own_mac[out_port]

        if not dst_mac:
            self.arp_waiting_queue[dst_ip].append((datapath, pkt, in_port))
            self.send_arp_request(datapath, out_port, self.port_to_own_mac[out_port],
                                  self.port_to_own_ip[out_port], dst_ip)
            return

        # Build match and actions
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_dst=dst_ip
        )
        actions = [
            parser.OFPActionDecNwTtl(),
            parser.OFPActionSetField(eth_src=src_mac_for_out_port),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionOutput(out_port)
        ]

        # Install flow and forward the packet
        self.add_flow(datapath, priority=10, match=match, actions=actions)

        # Send the current packet out immediately
        data = pkt.data
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    def forward_ip_packet(self, datapath, pkt, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        dst_ip = ip_pkt.dst

        dst_mac = self.arp_table.get(dst_ip)
        if dst_mac is None:
            # Shouldn't happen if this is called correctly
            return

        out_port = self.ip_to_port.get(dst_ip)
        if out_port is None:
            # Can't forward to unknown port
            return

        src_mac = self.port_to_own_mac[out_port]

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip)

        actions = [
            parser.OFPActionDecNwTtl(),
            parser.OFPActionSetField(eth_src=src_mac),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionOutput(out_port)
        ]
        self.add_flow(datapath, 10, match, actions)

        # Rebuild Ethernet frame with updated MACs
        new_eth = ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=eth_pkt.ethertype)

        # Serialize new packet
        out_pkt = packet.Packet()
        out_pkt.add_protocol(new_eth)
        out_pkt.add_protocol(ip_pkt)
        out_pkt.serialize()


        out_msg = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=out_pkt.data
        )
        datapath.send_msg(out_msg)


    def send_arp_request(self, datapath, out_port, src_mac, src_ip, target_ip):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        eth = ethernet.ethernet(dst="ff:ff:ff:ff:ff:ff", src=src_mac, ethertype=ether_types.ETH_TYPE_ARP)
        arp_req = arp.arp(opcode=arp.ARP_REQUEST,
                      src_mac=src_mac, src_ip=src_ip,
                      dst_mac="00:00:00:00:00:00", dst_ip=target_ip)
        pkt = packet.Packet()
        pkt.add_protocol(eth)
        pkt.add_protocol(arp_req)
        pkt.serialize()

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath,
                               buffer_id=ofproto.OFP_NO_BUFFER,
                               in_port=ofproto.OFPP_CONTROLLER,
                               actions=actions,
                               data=pkt.data)
        datapath.send_msg(out)

    def get_out_port_for_ip(self, dst_ip):
        ip = ipaddress.IPv4Address(dst_ip)

        subnet_to_port = {
            ipaddress.IPv4Network("10.0.1.0/24"): 1,
            ipaddress.IPv4Network("10.0.2.0/24"): 2,
            ipaddress.IPv4Network("192.168.1.0/24"): 3,
        }

        for subnet, port in subnet_to_port.items():
            if ip in subnet:
                return port

        return None

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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import arp, ethernet, ether_types, icmp, ipv4, packet

class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Here you can initialize the data structures you want to keep at the controller
        self.mac_to_port = {} # {dpid: {mac: port}}
        self.arp_table = {}
        self.packet_queue = {}
        # Router port MACs assumed by the controller
        self.port_to_own_mac = {
            1: "00:00:00:00:01:01",
            2: "00:00:00:00:01:02",
            3: "00:00:00:00:01:03"
        }
        # Router port (gateways) IP addresses assumed by the controller
        self.port_to_own_ip = {
            1: "10.0.1.1",
            2: "10.0.2.1",
            3: "192.168.1.1"
        }

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

        if eth.ethertype == ether_types.ETH_TYPE_LLDP: return

        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if arp_pkt:
            if arp_pkt.opcode == arp.ARP_REQUEST:
                self._handle_arp_request(datapath, in_port, arp_pkt)
            elif arp_pkt.opcode == arp.ARP_REPLY:
                self._handle_arp_reply(datapath, arp_pkt)
        elif ip_pkt:
            self.handle_ip_packet(datapath, in_port, ip_pkt, pkt)

        self.handle_switch_logic(msg, eth, in_port)

    def handle_switch_logic(self, msg, eth, in_port):
        datapath = msg.datapath; parser = datapath.ofproto_parser; ofproto = datapath.ofproto; dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        dst = eth.dst; src = eth.src

        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions)

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

    def _handle_arp_request(self, datapath, in_port, arp_pkt):
        for port, ip in self.port_to_own_ip.items():
            if arp_pkt.dst_ip == ip:
                self.logger.info(f"Received ARP request for router IP {ip}, replying with MAC.")
                self.send_arp_reply(datapath, port, arp_pkt.src_mac, arp_pkt.src_ip, arp_pkt.dst_ip)
                return

    def _handle_arp_reply(self, datapath, arp_pkt):
        self.logger.info(f"Received ARP reply: IP {arp_pkt.src_ip}, MAC {arp_pkt.src_mac}")
        self.arp_table[arp_pkt.src_ip] = arp_pkt.src_mac
        self.logger.info(f"ARP table updated: {arp_pkt.src_ip} -> {arp_pkt.src_mac}")
        self.send_buffered_packets(arp_pkt.src_ip)

    def send_arp_reply(self, datapath, port, target_mac, target_ip, dst_ip):
        parser = datapath.ofproto_parser; ofproto = datapath.ofproto
        src_mac = self.port_to_own_mac[port]; src_ip = self.port_to_own_ip[port]

        eth_pkt = ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP, dst=target_mac, src=src_mac)
        arp_pkt = arp.arp(hwtype=arp.ARP_HW_TYPE_ETHERNET, proto=ether_types.ETH_TYPE_IP, hlen=6, plen=4,
                          opcode=arp.ARP_REPLY, src_mac=src_mac, src_ip=src_ip, dst_mac=target_mac, dst_ip=target_ip)

        pkt = packet.Packet()
        pkt.add_protocol(eth_pkt); pkt.add_protocol(arp_pkt)
        pkt.serialize()

        actions = [parser.OFPActionOutput(port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions, data=pkt.data)
        datapath.send_msg(out)

    def handle_ip_packet(self, datapath, in_port, ip_pkt, full_pkt):
        ofproto = datapath.ofproto; parser = datapath.ofproto_parser
        dst_ip = ip_pkt.dst; src_ip = ip_pkt.src

        icmp_pkt = full_pkt.get_protocol(icmp.icmp)

        if icmp_pkt and dst_ip in self.port_to_own_ip.values() and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
            self.logger.info(f"ICMP Echo Request to {dst_ip}, replying")
            out_port = self.get_port_for_ip(dst_ip)
            self.send_icmp_echo_reply(datapath, out_port, full_pkt, ip_pkt, icmp_pkt)
            return

        if ip_pkt.ttl <= 1:
            self.logger.info(f"Dropping IP packet from {src_ip} to {dst_ip} due to TTL={ip_pkt.ttl}")
            return

        ip_pkt.ttl -=1; ip_pkt.csum = 0

        out_port = None
        for port, my_ip in self.port_to_own_ip.items():
            if not dst_ip.startswith(my_ip.rsplit('.', 1)[0]):
                out_port = port
                break

        if out_port is None:
            self.logger.info(f"No route found for IP {dst_ip}")
            return

        dst_mac = self.arp_table.get(dst_ip)
        if dst_mac is None:
            self.logger.info(f"MAC for {dst_ip} unknown, sending ARP request and buffering packet")
            self.send_arp_request(datapath, out_port, dst_ip)
            self.buffer_packet(dst_ip, datapath, out_port, full_pkt)
            return

        src_mac = self.port_to_own_mac[out_port]

        eth = full_pkt.get_protocol(ethernet.ethernet)
        eth.dst = dst_mac; eth.src = src_mac

        pkt = packet.Packet()
        pkt.add_protocol(eth); pkt.add_protocol(ip_pkt)
        if icmp_pkt: pkt.add_protocol(icmp_pkt)
        pkt.serialize()

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=pkt.data)
        datapath.send_msg(out)

    def send_arp_request(self, datapath, port, target_ip):
        parser = datapath.ofproto_parser; ofproto = datapath.ofproto
        src_mac = self.port_to_own_mac[port]; src_ip = self.port_to_own_ip[port]

        eth_pkt = ethernet.ethernet(dst="ff:ff:ff:ff:ff:ff", src=src_mac,
                                    ethertype=ether_types.ETH_TYPE_ARP)
        arp_req = arp.arp(opcode=arp.ARP_REQUEST, src_mac=src_mac, src_ip=src_ip,
                          dst_mac="00:00:00:00:00:00", dst_ip=target_ip)
        pkt = packet.Packet()
        pkt.add_protocol(eth_pkt); pkt.add_protocol(arp_req)
        pkt.serialize()

        actions = [parser.OFPActionOutput(port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)
        datapath.send_msg(out)

    def buffer_packet(self, ip, datapath, out_port, pkt):
        self.packet_queue.setdefault(ip, [])
        self.packet_queue[ip].append((datapath, out_port, pkt))

    def send_buffered_packets(self, ip):
        if ip not in self.packet_queue: return

        for datapath, out_port, full_pkt in self.packet_queue[ip]:
            parser = datapath.ofproto_parser; ofproto = datapath.ofproto

            eth = full_pkt.get_protocol(ethernet.ethernet)
            ip_pkt = full_pkt.get_protocol(ipv4.ipv4)
            src_mac = self.port_to_own_mac[out_port]
            dst_mac = self.arp_table[ip]

            eth.src = src_mac; eth.dst = dst_mac

            if ip_pkt.ttl <= 1: continue
            ip_pkt.ttl -= 1; ip_pkt.csum = 0

            pkt = packet.Packet()
            pkt.add_protocol(eth); pkt.add_protocol(ip_pkt)
            pkt.serialize()

            actions = [parser.OFPActionOutput(out_port)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)
            datapath.send_msg(out)
        del self.packet_queue[ip]

    def send_icmp_echo_reply(self, datapath, out_port, full_pkt, ip_pkt, icmp_pkt):
        parser = datapath.ofproto_parser; ofproto = datapath.ofproto
        src_ip = ip_pkt.dst; dst_ip = ip_pkt.src
        src_mac = self.port_to_own_mac[out_port]; dst_mac = self.arp_table.get(dst_ip)

        if not dst_mac:
            self.logger.info(f"MAC for ICMP reply to {dst_ip} not known, sending ARP")
            self.send_arp_request(datapath, out_port, dst_ip)
            self.buffer_packet(dst_ip, datapath, out_port, full_pkt)
            return

        echo_reply = icmp.icmp(type_=icmp.ICMP_ECHO_REPLY, code=0, csum=0, data=icmp_pkt.data)

        eth = full_pkt.get_protocol(ethernet.ethernet)
        eth_pkt = ethernet.ethernet(ethertype=ether_types.ETH_TYPE_IP, dst=dst_mac, src=src_mac)
        ip_reply = ipv4.ipv4(dst=dst_ip, src=src_ip, proto=ip_pkt.proto, ttl=64)

        pkt = packet.Packet()
        pkt.add_protocol(eth_pkt); pkt.add_protocol(ip_reply); pkt.add_protocol(echo_reply)
        pkt.serialize()

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)
        datapath.send_msg(out)

    def get_port_for_ip(self, ip):
        for port, subnet_ip in self.port_to_own_ip.items():
            if ip.startswith(subnet_ip.rsplit('.', 1)[0]): return port
        return None

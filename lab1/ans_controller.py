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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import mac as mac_lib
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import tcp

class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Here you can initialize the data structures you want to keep at the controller
        # Router port MACs assumed by the controller
        self.port_to_own_mac = {}

        # Router port (gateways) IP addresses assumed by the controller
        self.port_to_own_ip = {}

        self.arp_table = {}

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
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if not eth_pkt: return

        if eth_pkt.ethertype == ether_types.ETH_TYPE_ARP:
            self.handle_arp(datapath, msg, pkt, eth_pkt, pkt.get_protocol(arp.arp))
        elif eth_pkt.ethertype == ether_types.ETH_TYPE_IP:
            self.handle_router_packet(datapath, msg, pkt, eth_pkt, pkt.get_protocol(ipv4.ipv4))
        else:
            self.handle_switch_packet(datapath, msg, pkt, eth_pkt)

    def handle_switch_packet(self, datapath, msg, pkt, eth):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.port_to_own_mac.setdefault(datapath.id, {})

        dst = eth.dst
        src = eth.src

        in_port = msg.match['in_port']
        self.logger.info("packet in %s %s %s %s", datapath.id, src, dst, in_port)
        self.port_to_own_mac[datapath.id][src] = in_port


        if dst in self.port_to_own_mac[datapath.id]:
            out_port = self.port_to_own_mac[datapath.id][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        out = parser.OFPPacketOut(datapath=datapath,
                                           buffer_id=ofproto.OFP_NO_BUFFER,
                                           in_port=in_port, actions=actions,
                                           data=msg.data)
        datapath.send_msg(out)

    def handle_router_packet(self, datapath, msg, pkt, eth, ip_pkt):
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dst = ip_pkt.dst
        src = ip_pkt.src
        in_port = msg.match['in_port']

        if ip_pkt.ttl <= 1: return

        out_port = self.get_route(dpid, dst)
        if out_port is None or out_port == in_port: return

        dst_mac = self.arp_table[dpid][dst]
        if dst_mac:
            router_out_mac = self.port_to_own_mac[dpid][out_port]['mac']
            if not router_out_mac: return
            actions = [parser.OFPActionDecNwTtl(), parser.OFPActionSetField(eth_src=router_out_mac),
                       parser.OFPActionSetField(eth_dst=dst_mac), parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ID, ipv4_dst=dst)
            self.add_flow(datapath, 5, match, actions, idle_timeout=30)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER: data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
        else:
            self.send_arp_request(datapath, out_port, dst)

    def handle_arp(self, datapath, msg, pkt, eth, arp_pkt):
        dpid = datapath.id; ofproto = datapath.ofproto; parser = datapath.ofproto_parser
        src_ip = arp_pkt.src_ip; src_mac = arp_pkt.src_mac
        in_port = msg.match['in_port']
        self.arp_table.setdefault(dpid, {});

        if self.arp_table[dpid].get(src_ip) != src_mac:
            self.arp_table[dpid][src_ip] = src_mac

        target_ip = arp_pkt.dst_ip; target_mac = None
        for port_no, port_data in self.port_to_own_ip.get(dpid, {}).items():
            if port_data['ip'] = target_ip: target_mac = port_data['mac']; break
        if arp_pkt.opcode = arp.ARP_REQUEST and target_mac:
            reply_pkt = packet.Packet();
            reply_pkt.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP, dst=src_mac, src=target_mac))
            reply_pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=target_mac, src_ip=target_ip, dst_mac=src_mac, dst_ip=src_ip))
            reply_pkt.serialize()
            actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=reply_pkt.data)
            datapath.send_msg(out)
        elif arp_pkt.opcode == arp.ARP_REPLY:
            if self.arp_table[dpid].get(src_ip) == src_mac:
                self.logger.info(f"ROUTER {dpid:x}: Received ARP Reply from {src_ip} ({src_mac}) - mapping learned/updated.")

    def get_route(self, dpid, dst):
        best_match_port = None; longest_prefix = -1
        try: dst_ip_addr = ipaddress.ip_address(dst)
        except ValueError: return None

        for port_no, port_data in self.port_to_own_ip[dpid].items():
            try:
                network = ipaddress.ip_network(port_data['subnet'], strict=False)
                if dst_ip_addr in network:
                        if network.prefixlen > longest_prefix:
                            longest_prefix = network.prefixlen
                            best_match_port = port_no
            except ValueError: continue
            except Exception as e: continue
        return best_match_port

    def send_arp_request(self, datapath, out_port, target_ip):
        dpid = datapath.id; ofproto = datapath.ofproto; parser = datapath.ofproto_parser
        info = self.port_to_own_ip[dpid][out_port]
        if not info: return

        mac = info['mac']; ip = info['ip']
        req_pkt = packet.Packet()
        req_pkt.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP, dst=mac_lib.BROADCAST_ST, src=mac))
        req_pkt.add_protocol(arp.arp(opcode=arp.ARP_REQUEST, src_mac=mac, src_ip=ip, dst_mac=mac_lib.DONTCARE_STR, dst_ip=target_ip))
        req_pkt.serialize();
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=req_pkt.data)
        datapath.send_msg(out)

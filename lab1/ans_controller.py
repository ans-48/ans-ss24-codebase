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
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib import mac as mac_lib
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4

class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]


    # Here you can initialize the data structures you want to keep at the controller
    # Router port MACs assumed by the controller
        
    S1_DPID = 0x11
    S2_DPID = 0x12
    S3_DPID = 0x13

    ROUTER_PORTS_CONFIG = {
        S3_DPID: {
            1: {'ip': '10.0.1.1', 'mac': '00:00:00:00:01:01', 'subnet': '10.0.1.0/24'},
            2: {'ip': '10.0.2.1', 'mac': '00:00:00:00:01:02', 'subnet': '10.0.2.0/24'},
            3: {'ip': '192.168.1.1', 'mac': '00:00:00:00:01:03', 'subnet': '192.168.1.0/24'}
        }
    }
    H1_IP = '10.0.1.2'
    H2_IP = '10.0.1.3'
    SER_IP = '10.0.2.2'
    EXT_IP = '192.168.1.123'
    INTERNAL_HOST_IPS = [H1_IP, H2_IP, SER_IP]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)
        
        
        self.mac_to_port = {}
        self.arp_table = {self.S3_DPID: {}}
        self.logger.info("ANS Lab1 Controller Initialized (Merged with Template)")


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

            
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def install_router_base_rules(self, datapath):
        parser = datapath.ofproto_parser
        priority_high = 10
        for internal_ip in self.INTERNAL_HOST_IPS:
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=1, # ICMP
                                    icmpv4_type=icmp.ICMP_ECHO_REQUEST,
                                    ipv4_src=self.EXT_IP, ipv4_dst=internal_ip)
            self.add_flow(datapath, priority_high, match, [])
            self.logger.info(f"  Rule Added: Block ICMP Echo Req from {self.EXT_IP} -> {internal_ip}")

        protocols_to_block = {6: 'TCP', 17: 'UDP'}
        for proto_num in protocols_to_block.keys():
            match1 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=proto_num,
                                     ipv4_src=self.EXT_IP, ipv4_dst=self.SER_IP)
            self.add_flow(datapath, priority_high, match1, [])
            match2 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=proto_num,
                                     ipv4_src=self.SER_IP, ipv4_dst=self.EXT_IP)
            self.add_flow(datapath, priority_high, match2, [])
            self.logger.info(f"  Rule Added: Block {protocols_to_block[proto_num]} between {self.EXT_IP} and {self.SER_IP}")

        router_s3_ports_info = self.ROUTER_PORTS_CONFIG.get(self.S3_DPID, {})
        all_gateway_ips_s3 = [p['ip'] for p in router_s3_ports_info.values()]
        for in_port_num, port_info in router_s3_ports_info.items():
            my_gateway_ip = port_info['ip']
            for target_gw_ip in all_gateway_ips_s3:
                if my_gateway_ip == target_gw_ip:
                    continue
                match = parser.OFPMatch(in_port=in_port_num, eth_type=ether_types.ETH_TYPE_IP,
                                        ip_proto=1, # ICMP
                                        icmpv4_type=icmp.ICMP_ECHO_REQUEST,
                                        ipv4_dst=target_gw_ip)
                self.add_flow(datapath, priority_high, match, [])
                self.logger.info(f"  Rule Added: Block ICMP Echo Req on Port {in_port_num} to other gateway {target_gw_ip}")
        
        for internal_ip in self.INTERNAL_HOST_IPS:
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ip_proto=1, # ICMP
                icmpv4_type=icmp.ICMP_ECHO_REQUEST,
                ipv4_src=internal_ip,
                ipv4_dst=self.EXT_IP
            )
            self.add_flow(datapath, priority_high, match, [])
            self.logger.info(f"  Rule Added: Block ICMP Echo Req from {internal_ip} -> {self.EXT_IP}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
                 

        if not eth or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        if dpid == self.S1_DPID or dpid == self.S2_DPID:
            self.handle_switch_packet(datapath, msg, in_port, pkt, eth)
        elif dpid == self.S3_DPID:
            self.install_router_base_rules(datapath)
            self.handle_router_packet(datapath, msg, in_port, pkt, eth)
        else:
            self.logger.info(f"Packet-in from unknown DPID {dpid:x}. Performing basic L2 learning.")
            dst_mac = eth.dst
            src_mac = eth.src

            self.mac_to_port.setdefault(dpid, {})
            self.logger.info("packet in %s %s %s %s", dpid, src_mac, dst_mac, in_port)
            self.mac_to_port[dpid][src_mac] = in_port

            if dst_mac in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst_mac]
            else:
                out_port = ofproto.OFPP_FLOOD
            
            actions = [parser.OFPActionOutput(out_port)]

            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(eth_dst=dst_mac)
                self.add_flow(datapath, 1, match, actions)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

    def handle_switch_packet(self, datapath, msg, in_port, pkt, eth_frame):
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        src_mac = eth_frame.src
        dst_mac = eth_frame.dst

        self.mac_to_port.setdefault(dpid, {})
        if self.mac_to_port[dpid].get(src_mac) != in_port:
            self.logger.info(f"SWITCH {dpid:x}: Learning MAC {src_mac} on Port {in_port}")
        self.mac_to_port[dpid][src_mac] = in_port

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(eth_dst=dst_mac)
            self.add_flow(datapath, 1, match, actions)
        else:
            out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def handle_router_packet(self, datapath, msg, in_port, pkt, eth_frame):
        if eth_frame.ethertype == ether_types.ETH_TYPE_ARP:
            arp_header = pkt.get_protocol(arp.arp)
            if arp_header:
                self.handle_arp(datapath, msg, in_port, pkt, eth_frame, arp_header)
                return
        elif eth_frame.ethertype == ether_types.ETH_TYPE_IP:
            ipv4_header = pkt.get_protocol(ipv4.ipv4)
            if ipv4_header:
                self.handle_ip(datapath, msg, in_port, pkt, eth_frame, ipv4_header)
                return

    def handle_arp(self, datapath, msg, in_port, pkt, eth_frame, arp_pkt):
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        src_ip = arp_pkt.src_ip
        src_mac = arp_pkt.src_mac

        if dpid == self.S3_DPID:
            if self.arp_table[dpid].get(src_ip) != src_mac:
                self.arp_table[dpid][src_ip] = src_mac
                self.logger.info(f"ROUTER {dpid:x}: Learned ARP: {src_ip} -> {src_mac} (from Port {in_port})")
        
        target_ip = arp_pkt.dst_ip
        my_mac_for_target_ip = None

        if dpid == self.S3_DPID:
            for port_no, port_data in self.ROUTER_PORTS_CONFIG.get(dpid, {}).items():
                if port_data['ip'] == target_ip:
                    my_mac_for_target_ip = port_data['mac']
                    break
        
        if arp_pkt.opcode == arp.ARP_REQUEST and my_mac_for_target_ip:
            self.logger.info(f"ROUTER {dpid:x}: Received ARP Request for my IP {target_ip} from {src_ip} ({src_mac})")
            reply_pkt_obj = packet.Packet()
            reply_pkt_obj.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP,
                                                   dst=src_mac, src=my_mac_for_target_ip))
            reply_pkt_obj.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                         src_mac=my_mac_for_target_ip, src_ip=target_ip,
                                         dst_mac=src_mac, dst_ip=src_ip))
            reply_pkt_obj.serialize()
            actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=reply_pkt_obj.data)
            datapath.send_msg(out)
            self.logger.info(f"ROUTER {dpid:x}: Sent ARP Reply: {target_ip} is at {my_mac_for_target_ip}")
        elif arp_pkt.opcode == arp.ARP_REPLY:
            if dpid == self.S3_DPID and self.arp_table[dpid].get(src_ip) == src_mac:
                 self.logger.info(f"ROUTER {dpid:x}: Received ARP Reply from {src_ip} ({src_mac}) - mapping learned/updated.")

    def handle_ip(self, datapath, msg, in_port, pkt, eth_frame, ip_pkt):
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dst_ip = ip_pkt.dst

        if ip_pkt.ttl <= 1:
            self.logger.debug(f"ROUTER {dpid:x}: TTL too low for IP packet from {ip_pkt.src} to {dst_ip}. Dropping.")
            return

        my_interface_info = None
        if dpid == self.S3_DPID:
            for port_data in self.ROUTER_PORTS_CONFIG.get(dpid, {}).values():
                if port_data['ip'] == dst_ip:
                    my_interface_info = port_data
                    break
        
        if my_interface_info:
            icmp_header = pkt.get_protocol(icmp.icmp)
            if icmp_header and icmp_header.type == icmp.ICMP_ECHO_REQUEST:
                self.send_icmp_reply(datapath, in_port, pkt, eth_frame, ip_pkt, icmp_header)
            return 

        if dpid != self.S3_DPID:
            self.logger.warning(f"Non-router switch {dpid:x} received IP packet for routing. This shouldn't happen often.")
            return

        out_port = self.get_route(dpid, dst_ip)

        if out_port is None or out_port == in_port:
            self.logger.debug(f"ROUTER {dpid:x}: No route or invalid route for {dst_ip} from port {in_port}. Dropping.")
            return

        next_hop_ip = dst_ip
        dst_mac_for_next_hop = self.arp_table.get(dpid, {}).get(next_hop_ip)

        if dst_mac_for_next_hop:
            router_out_mac = self.ROUTER_PORTS_CONFIG.get(dpid, {}).get(out_port, {}).get('mac')
            if not router_out_mac:
                self.logger.error(f"ROUTER {dpid:x}: Missing MAC for out_port {out_port}. Cannot forward.")
                return

            actions = [
                parser.OFPActionDecNwTtl(),
                parser.OFPActionSetField(eth_src=router_out_mac),
                parser.OFPActionSetField(eth_dst=dst_mac_for_next_hop),
                parser.OFPActionOutput(out_port)
            ]
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip)
            self.add_flow(datapath, 5, match, actions)
            self.logger.info(f"ROUTER {dpid:x}: Installed routing flow: DstIP={dst_ip} -> Port={out_port}/NextHopMAC={dst_mac_for_next_hop} (Prio=5)")
            
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
        else:
            self.logger.info(f"ROUTER {dpid:x}: No ARP entry for next hop {next_hop_ip} (for {dst_ip}). Sending ARP request on port {out_port}.")
            self.send_arp_request(datapath, out_port, next_hop_ip)

    def get_route(self, dpid, dst_ip_str):
        if dpid != self.S3_DPID: return None

        best_match_port = None
        longest_prefix = -1
        try:
            dst_ip_addr = ipaddress.ip_address(dst_ip_str)
        except ValueError:
            self.logger.error(f"ROUTER {dpid:x}: Invalid destination IP format: {dst_ip_str}")
            return None

        for port_no, port_data in self.ROUTER_PORTS_CONFIG.get(dpid, {}).items():
            try:
                network = ipaddress.ip_network(port_data['subnet'], strict=False)
                if dst_ip_addr in network:
                    if network.prefixlen > longest_prefix:
                        longest_prefix = network.prefixlen
                        best_match_port = port_no
            except ValueError:
                self.logger.error(f"ROUTER {dpid:x}: Invalid subnet format in ROUTER_PORTS_CONFIG: {port_data.get('subnet', 'N/A')}")
                continue
            except Exception as e:
                self.logger.error(f"ROUTER {dpid:x}: Error processing network {port_data.get('subnet', 'N/A')} for IP {dst_ip_str}: {e}")
                continue
        
        if best_match_port is not None:
            self.logger.debug(f"ROUTER {dpid:x}: Route for {dst_ip_str} is out_port {best_match_port} (subnet {self.ROUTER_PORTS_CONFIG[dpid][best_match_port]['subnet']})")
        else:
            self.logger.debug(f"ROUTER {dpid:x}: No route found for {dst_ip_str}")
        return best_match_port

    def send_arp_request(self, datapath, out_port, target_ip):
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        my_info = self.ROUTER_PORTS_CONFIG.get(dpid, {}).get(out_port)
        if not my_info:
            self.logger.error(f"ROUTER {dpid:x}: Cannot send ARP from unconfigured port {out_port}.")
            return
        
        my_mac = my_info['mac']
        my_ip = my_info['ip']

        req_pkt_obj = packet.Packet()
        req_pkt_obj.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP,
                                             dst=mac_lib.BROADCAST_STR, src=my_mac))
        req_pkt_obj.add_protocol(arp.arp(opcode=arp.ARP_REQUEST,
                                   src_mac=my_mac, src_ip=my_ip,
                                   dst_mac=mac_lib.DONTCARE_STR, dst_ip=target_ip))
        req_pkt_obj.serialize()
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=req_pkt_obj.data)
        datapath.send_msg(out)
        self.logger.debug(f"ROUTER {dpid:x}: Sent ARP request for {target_ip} via port {out_port}")

    def send_icmp_reply(self, datapath, in_port, pkt_in, eth_in, ipv4_in, icmp_in):
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        my_ip_on_router = ipv4_in.dst
        my_mac_on_router = None

        for port_data in self.ROUTER_PORTS_CONFIG.get(dpid, {}).values():
            if port_data['ip'] == my_ip_on_router:
                my_mac_on_router = port_data['mac']
                break
        
        if not my_mac_on_router:
            self.logger.error(f"ROUTER {dpid:x}: Cannot find MAC for own IP {my_ip_on_router} to send ICMP reply.")
            return

        reply_pkt_obj = packet.Packet()
        reply_pkt_obj.add_protocol(ethernet.ethernet(ethertype=eth_in.ethertype,
                                               dst=eth_in.src, src=my_mac_on_router))
        reply_pkt_obj.add_protocol(ipv4.ipv4(dst=ipv4_in.src, src=my_ip_on_router,
                                       proto=ipv4_in.proto, ttl=64))
        reply_pkt_obj.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                                       code=icmp.ICMP_ECHO_REPLY_CODE,
                                       csum=0, data=icmp_in.data))
        reply_pkt_obj.serialize()
        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=reply_pkt_obj.data)
        datapath.send_msg(out)
        self.logger.info(f"ROUTER {dpid:x}: Sent ICMP Echo Reply from {my_ip_on_router} to {ipv4_in.src}")

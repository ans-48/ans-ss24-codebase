# File: ans_controller.py (Final Working Version)

import ipaddress # Use standard Python library for IP addresses/networks

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import ip as ip_lib # Keep for IPNetwork potentially? No, use ipaddress fully.
from ryu.lib import mac as mac_lib
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.ofproto import ofproto_v1_3

class AnsController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    S1_DPID = 0x11
    S2_DPID = 0x12
    S3_DPID = 0x13

    ROUTER_PORTS = {
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
        super(AnsController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_table = {self.S3_DPID: {}}
        self.logger.info("ANS Lab1 Controller Initialized (Final Fixes)")

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] # Use OFPIT_
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst, idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        # self.logger.info(f"Device DPID {dpid:x} connected.")
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        # self.logger.info(f"  -> Installed Table-Miss Flow Entry for DPID {dpid:x}")
        if dpid == self.S3_DPID:
            # self.logger.info(f"Router {dpid:x} detected. Installing base security rules.")
            self.install_router_base_rules(datapath)

    def install_router_base_rules(self, datapath):
        parser = datapath.ofproto_parser
        dpid = datapath.id
        priority_high = 10
        # self.logger.info(f"Router {dpid:x}: Installing base rules with Priority {priority_high}")
        for internal_ip in self.INTERNAL_HOST_IPS:
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=1,
                                    icmpv4_type=icmp.ICMP_ECHO_REQUEST, ipv4_src=self.EXT_IP,
                                    ipv4_dst=internal_ip)
            self.add_flow(datapath, priority_high, match, [])
            # self.logger.info(f"  Rule Added: Block ICMP Echo Req from {self.EXT_IP} -> {internal_ip}")
        protocols_to_block = {6: 'TCP', 17: 'UDP'}
        for proto_num, proto_name in protocols_to_block.items():
            match1 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=proto_num,
                                     ipv4_src=self.EXT_IP, ipv4_dst=self.SER_IP)
            self.add_flow(datapath, priority_high, match1, [])
            match2 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=proto_num,
                                     ipv4_src=self.SER_IP, ipv4_dst=self.EXT_IP)
            self.add_flow(datapath, priority_high, match2, [])
            # self.logger.info(f"  Rule Added: Block {proto_name} traffic between {self.EXT_IP} and {self.SER_IP}")
        router_ports_info = self.ROUTER_PORTS.get(dpid, {})
        all_gateway_ips = [p['ip'] for p in router_ports_info.values()]
        for in_port_num, port_info in router_ports_info.items():
            my_gateway_ip = port_info['ip']
            for target_gw_ip in all_gateway_ips:
                if my_gateway_ip == target_gw_ip: continue
                match = parser.OFPMatch(in_port=in_port_num, eth_type=ether_types.ETH_TYPE_IP,
                                        ip_proto=1, icmpv4_type=icmp.ICMP_ECHO_REQUEST,
                                        ipv4_dst=target_gw_ip)
                self.add_flow(datapath, priority_high, match, [])
                # self.logger.info(f"  Rule Added: Block ICMP Echo Req on Port {in_port_num} to other gateway {target_gw_ip}")

        # Rule 4: Block PING (ICMP Echo Request) FROM internal hosts TO ext
        # (Add this block to match the PDF pingall graphic exactly)
        # --------------------------------------------------------------------------
        for internal_ip in self.INTERNAL_HOST_IPS:
             match = parser.OFPMatch(
                 eth_type=ether_types.ETH_TYPE_IP,       # IP packet
                 ip_proto=1,                             # ICMP protocol
                 icmpv4_type=icmp.ICMP_ECHO_REQUEST,     # Echo Request
                 ipv4_src=internal_ip,                   # Source is internal host
                 ipv4_dst=self.EXT_IP                    # Destination is external host
             )
             actions = [] # Drop packet
             self.add_flow(datapath, priority_high, match, actions)
             self.logger.info(f"  Rule Added: Block ICMP Echo Req from {internal_ip} -> {self.EXT_IP}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg; datapath = msg.datapath; ofproto = datapath.ofproto; parser = datapath.ofproto_parser
        in_port = msg.match['in_port']; dpid = datapath.id; pkt = packet.Packet(msg.data); eth = pkt.get_protocol(ethernet.ethernet)
        if not eth or eth.ethertype == ether_types.ETH_TYPE_LLDP: return
        if dpid == self.S1_DPID or dpid == self.S2_DPID:
            self.handle_switch_packet(datapath, msg, in_port, pkt, eth)
        elif dpid == self.S3_DPID:
            self.handle_router_packet(datapath, msg, in_port, pkt, eth)

    def handle_switch_packet(self, datapath, msg, in_port, pkt, eth):
        dpid = datapath.id; ofproto = datapath.ofproto; parser = datapath.ofproto_parser; src = eth.src; dst = eth.dst
        self.mac_to_port.setdefault(dpid, {});
        # Log only if new/changed
        # if self.mac_to_port[dpid].get(src) != in_port:
        #    self.logger.info(f"SWITCH {dpid:x}: Learning MAC {src} is on Port {in_port}")
        self.mac_to_port[dpid][src] = in_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]; actions = [parser.OFPActionOutput(out_port)]; match = parser.OFPMatch(eth_dst=dst)
            self.add_flow(datapath, 1, match, actions, idle_timeout=20)
        else: out_port = ofproto.OFPP_FLOOD; actions = [parser.OFPActionOutput(out_port)]
        data = None;
        if msg.buffer_id == ofproto.OFP_NO_BUFFER: data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def handle_router_packet(self, datapath, msg, in_port, pkt, eth):
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
             arp_pkt = pkt.get_protocol(arp.arp);
             if arp_pkt: self.handle_arp(datapath, msg, in_port, pkt, eth, arp_pkt); return
        elif eth.ethertype == ether_types.ETH_TYPE_IP:
             ip_pkt = pkt.get_protocol(ipv4.ipv4);
             if ip_pkt: self.handle_ip(datapath, msg, in_port, pkt, eth, ip_pkt); return

    def handle_arp(self, datapath, msg, in_port, pkt, eth, arp_pkt):
        dpid = datapath.id; ofproto = datapath.ofproto; parser = datapath.ofproto_parser; src_ip = arp_pkt.src_ip; src_mac = arp_pkt.src_mac
        self.arp_table.setdefault(dpid, {});
        if self.arp_table[dpid].get(src_ip) != src_mac: # Learn only if new or changed
            self.arp_table[dpid][src_ip] = src_mac
            self.logger.info(f"ROUTER {dpid:x}: Learned ARP: {src_ip} -> {src_mac} (from Port {in_port})")
        target_ip = arp_pkt.dst_ip; my_mac_for_target_ip = None
        for port_no, port_data in self.ROUTER_PORTS.get(dpid, {}).items():
             if port_data['ip'] == target_ip: my_mac_for_target_ip = port_data['mac']; break
        if arp_pkt.opcode == arp.ARP_REQUEST and my_mac_for_target_ip:
            # self.logger.info(f"ROUTER {dpid:x}: Received ARP Request for my IP {target_ip} from {src_ip}")
            reply_pkt = packet.Packet(); reply_pkt.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP, dst=src_mac, src=my_mac_for_target_ip))
            reply_pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=my_mac_for_target_ip, src_ip=target_ip, dst_mac=src_mac, dst_ip=src_ip))
            reply_pkt.serialize(); actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=reply_pkt.data)
            datapath.send_msg(out)
            # self.logger.info(f"ROUTER {dpid:x}: Sent ARP Reply: {target_ip} is at {my_mac_for_target_ip}")
        elif arp_pkt.opcode == arp.ARP_REPLY:
             if self.arp_table[dpid].get(src_ip) == src_mac: # Check if learning actually happened
                 self.logger.info(f"ROUTER {dpid:x}: Received ARP Reply from {src_ip} ({src_mac}) - mapping learned/updated.")

    def handle_ip(self, datapath, msg, in_port, pkt, eth, ip_pkt):
        dpid = datapath.id; ofproto = datapath.ofproto; parser = datapath.ofproto_parser; dst_ip = ip_pkt.dst; src_ip = ip_pkt.src
        if ip_pkt.ttl <= 1: return
        my_interface_info = None
        for port_no, port_data in self.ROUTER_PORTS.get(dpid, {}).items():
            if port_data['ip'] == dst_ip: my_interface_info = port_data; break
        if my_interface_info:
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                 self.send_icmp_reply(datapath, in_port, pkt, eth, ip_pkt, icmp_pkt)
            return
        out_port = self.get_route(dpid, dst_ip)
        if out_port is None or out_port == in_port: return
        next_hop_ip = dst_ip; dst_mac = self.arp_table.get(dpid, {}).get(next_hop_ip)
        if dst_mac:
            router_out_mac = self.ROUTER_PORTS.get(dpid, {}).get(out_port, {}).get('mac')
            if not router_out_mac: return
            actions = [parser.OFPActionDecNwTtl(), parser.OFPActionSetField(eth_src=router_out_mac),
                       parser.OFPActionSetField(eth_dst=dst_mac), parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip)
            self.add_flow(datapath, 5, match, actions, idle_timeout=30)
            # self.logger.info(f"ROUTER {dpid:x}: Installed routing flow: DstIP={dst_ip} -> Port={out_port}/MAC={dst_mac} (Prio=5)")
            data = None;
            if msg.buffer_id == ofproto.OFP_NO_BUFFER: data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
        else:
            # self.logger.info(f"ROUTER {dpid:x}: No ARP entry for next hop {next_hop_ip} (needed for {dst_ip}). Sending ARP request.")
            self.send_arp_request(datapath, out_port, next_hop_ip);

    def get_route(self, dpid, dst_ip_str):
        best_match_port = None
        longest_prefix = -1
        try:
            dst_ip_addr = ipaddress.ip_address(dst_ip_str)
        except ValueError:
            # self.logger.error(f"ROUTER {dpid:x}: Invalid destination IP format received: {dst_ip_str}")
            return None
        for port_no, port_data in self.ROUTER_PORTS.get(dpid, {}).items():
            try:
                network = ipaddress.ip_network(port_data['subnet'], strict=False)
                if dst_ip_addr in network:
                    if network.prefixlen > longest_prefix:
                        longest_prefix = network.prefixlen
                        best_match_port = port_no
            except ValueError:
                 # self.logger.error(f"ROUTER {dpid:x}: Invalid subnet format in ROUTER_PORTS: {port_data.get('subnet', 'N/A')}")
                 continue
            except Exception as e: # Fixed typo
                 self.logger.error(f"ROUTER {dpid:x}: Error processing network {port_data.get('subnet', 'N/A')} for IP {dst_ip_str}: {e}")
                 continue
        return best_match_port

    def send_arp_request(self, datapath, out_port, target_ip):
        dpid = datapath.id; ofproto = datapath.ofproto; parser = datapath.ofproto_parser
        my_info = self.ROUTER_PORTS.get(dpid, {}).get(out_port);
        if not my_info: return
        my_mac = my_info['mac']; my_ip = my_info['ip']
        req_pkt = packet.Packet(); req_pkt.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP, dst=mac_lib.BROADCAST_STR, src=my_mac))
        req_pkt.add_protocol(arp.arp(opcode=arp.ARP_REQUEST, src_mac=my_mac, src_ip=my_ip, dst_mac=mac_lib.DONTCARE_STR, dst_ip=target_ip))
        req_pkt.serialize(); actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=req_pkt.data)
        datapath.send_msg(out)
        # self.logger.debug(f"ROUTER {dpid:x}: Sent ARP request for {target_ip} via port {out_port}")

    def send_icmp_reply(self, datapath, in_port, pkt_in, eth_in, ipv4_in, icmp_in):
        dpid = datapath.id; ofproto = datapath.ofproto; parser = datapath.ofproto_parser; my_ip = ipv4_in.dst; my_mac = None
        for port_no, port_data in self.ROUTER_PORTS.get(dpid, {}).items():
             if port_data['ip'] == my_ip: my_mac = port_data['mac']; break
        if not my_mac: return
        reply_pkt = packet.Packet(); reply_pkt.add_protocol(ethernet.ethernet(ethertype=eth_in.ethertype, dst=eth_in.src, src=my_mac))
        reply_pkt.add_protocol(ipv4.ipv4(dst=ipv4_in.src, src=my_ip, proto=ipv4_in.proto, ttl=64))
        reply_pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY, code=icmp.ICMP_ECHO_REPLY_CODE, csum=0, data=icmp_in.data))
        reply_pkt.serialize(); actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=reply_pkt.data)
        datapath.send_msg(out)
        # self.logger.info(f"ROUTER {dpid:x}: Sent ICMP Echo Reply from {my_ip} to {ipv4_in.src}")

import json
import time
import sys
import netaddr

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ether import ETH_TYPE_IP
from ryu.lib.ofctl_v1_3 import mod_flow_entry
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import udp
from ryu.lib.packet import tcp
from ryu import cfg

CONF = cfg.CONF
CONF.register_opts([
    cfg.StrOpt('rules', default='[]', help='rules'),])

class Lago_Firewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Lago_Firewall, self).__init__(*args, **kwargs)
        self.flow_info = {}
        self.rules = json.loads(CONF.rules)

        for rule in self.rules:
            self.flow_info[rule["priority"]] = rule

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        self.logger.info('switch joind: datapath: %061x' % datapath.id)

        #initialize
        for var in range(0,3):
            mod_flow_entry(datapath, {'table_id' : var}, ofproto.OFPFC_DELETE)

        for var in range(0,2):
            for ipproto in [6,17]:
                mod_flow_entry(datapath,
                               {'priority' : 1,
                                'table_id' : var,
                                'match' : {'dl_type' : 2048,
                                           'ip_proto' : ipproto},
                                'actions' :[{'type' : 'OUTPUT', 'port' : ofproto.OFPP_CONTROLLER}]},
                               ofproto.OFPFC_ADD)
                mod_flow_entry(datapath,
                               {'priority' : 1,
                                'table_id' : var,
                                'match' : {},
                                'actions' :[{'type' : 'GOTO_TABLE', 'table_id' : var+1}]},
                               ofproto.OFPFC_ADD)
        mod_flow_entry(datapath,
                       {'priority' : 1,
                        'table_id' : 2,
                        'match' : {'in_port':1},
                        'actions' :[{'type' : 'OUTPUT', 'port' :2}]},
                       ofproto.OFPFC_ADD)
        mod_flow_entry(datapath,
                       {'priority' : 1,
                        'table_id' : 2,
                        'match' : {'in_port':2},
                        'actions' :[{'type' : 'OUTPUT', 'port' :1}]},
                       ofproto.OFPFC_ADD)

        for k in self.flow_info.keys():
            self.add_flow_rules(datapath, ofproto, self.flow_info[k])

    def add_flow_rules(self, datapath, ofproto, rule):
        print rule
        _src_ipaddr = netaddr.IPNetwork(rule["src_ipaddr"])
        src_ip = str(_src_ipaddr)
        _dst_ipaddr = netaddr.IPNetwork(rule["dst_ipaddr"])
        dst_ip = str(_dst_ipaddr)

        self.port_list_src = self.calculate_port_mask(rule["src_port_min"], rule["src_port_max"], 0)
        self.port_list_dst = self.calculate_port_mask(rule["dst_port_min"], rule["dst_port_max"], 0)

        for l in self.port_list_src:
            for m in self.port_list_dst:
                metadata = str((l['key'] << 16) + m['key'])
                metadata_mask = str((l['mask'] << 16) + m['mask'])
                mod_flow_entry(datapath,
                               {'priority' : rule["priority"],
                                'table_id' : 2,
                                'match' : {'ipv4_src' : src_ip,
                                           'ipv4_dst' : dst_ip,
                                           'dl_type' : 2048,
                                           'ip_proto' : int(rule["ipproto"]),
                                           'metadata' : metadata + '/' + metadata_mask},
                                'actions' : []},
                               ofproto.OFPFC_ADD)

    def calculate_port_mask(self, port_min, port_max, length):
        port_list = []
        if length > 0:
            tmp_mask = (65535 << (16 - length)) & 65535
        else :
            tmp_mask = 0

        if ((port_min & tmp_mask) == port_min) and ((port_max | ~(tmp_mask)) & 65535 == port_max):
            if ((port_min & tmp_mask) != (port_max & tmp_mask)):
                length = length - 1
            if length > 0:
                tmp_mask = (65535 << (16 - length)) & 65535
            else:
                length = 0
            port_list.append({"key":port_min, "mask":tmp_mask})
            return port_list

        if ((port_min & tmp_mask) == (port_max & tmp_mask)):
            port_list.extend(self.calculate_port_mask(port_min, port_max, length + 1))
        else:
            port_list.extend(self.calculate_port_mask(port_min, (port_min | ~(tmp_mask)) & 65535, length + 1))
            port_list.extend(self.calculate_port_mask((port_max & (tmp_mask)), port_max, length + 1))
        return port_list


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = Packet(msg.data)
        pkt_udp = pkt.get_protocol(udp.udp)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        header_list = dict((p.protocol_name, p)
                           for p in pkt.protocols if type(p) != str)

        self.logger.info(header_list)

        if pkt_udp:
            src_port = pkt_udp.src_port
            dst_port = pkt_udp.dst_port
        elif pkt_tcp:
            src_port = pkt_tcp.src_port
            dst_port = pkt_tcp.dst_port

        for ipproto in [6,17]:
            mod_flow_entry(datapath,
                           {'priority' : 100,
                            'table_id' : 0,
                            'match' : {'tp_src': src_port,
                                       'dl_type': 2048,
                                       'ip_proto': ipproto},
                            'actions' :[{'type': 'WRITE_METADATA',
                                         'metadata': src_port << 16,
                                         'metadata_mask' : 4294901760},
                                        {'type': 'GOTO_TABLE',
                                         'table_id' : 1}]},
                           ofproto.OFPFC_ADD)
            mod_flow_entry(datapath,
                           {'priority' : 100,
                            'table_id' : 1,
                            'match' : {'tp_dst': dst_port,
                                       'dl_type': 2048,
                                       'ip_proto': ipproto},
                            'actions' :[{'type': 'WRITE_METADATA',
                                         'metadata': dst_port,
                                         'metadata_mask': 65535},
                                        {'type' : 'GOTO_TABLE',
                                         'table_id' : 2}]},
                           ofproto.OFPFC_ADD)

            self.packet_out(datapath, pkt)

    def packet_out(self, datapath, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt.serialize()
        self.logger.info("packet_out %s" %(pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(ofproto.OFPP_TABLE, 0)]
        out = parser.OFPPacketOut(datapath = datapath, buffer_id = ofproto.OFP_NO_BUFFER,
                                  in_port = ofproto.OFPP_CONTROLLER, actions = actions,
                                  data = data)
        datapath.send_msg(out)


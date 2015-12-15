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

class flow_table(object):
    def __init__(self, src_ipaddr, dst_ipaddr, src_port_min, src_port_max, dst_port_min, dst_port_max, ipproto):
        self.src_ipaddr = src_ipaddr
        self.dst_ipaddr = dst_ipaddr
        self.src_port_min = src_port_min
        self.src_port_max = src_port_max
        self.dst_port_min = dst_port_min
        self.dst_port_max = dst_port_max
        self.ipproto = ipproto

class Lago_Firewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Lago_Firewall, self).__init__(*args, **kwargs)
        self.flow_info = {}
        self.rules = json.loads(CONF.rules)
        print self.rules
        i = 0
        for r in self.rules:
            src_ipaddr = r['src_ipaddr']
            dst_ipaddr = r['dst_ipaddr']
            src_port_min = r['src_port_min']
            src_port_max = r['src_port_max']
            dst_port_min = r['dst_port_min']
            dst_port_max = r['dst_port_max']
            ipproto = r['ipproto']
            self.flow_info[i] = flow_table(src_ipaddr, dst_ipaddr, src_port_min, src_port_max,dst_port_min, dst_port_max, ipproto)
            i = i+1

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto

        for var in range(0,3):
            mod_flow_entry(datapath, {'table_id' : var}, ofproto.OFPFC_DELETE)

        #initialize
        for var in range(0,2):
            for ipproto in [6,17]:
                mod_flow_entry(datapath,
                               {'priority' : 10,
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

        priority = 100
        self.logger.info('switch joind: datapath: %061x' % datapath.id)
        tmp = 0

        for k in self.flow_info.keys():
            _src_ipaddr = netaddr.IPNetwork(self.flow_info[k].src_ipaddr)
            src_ip = str(_src_ipaddr)
            _dst_ipaddr = netaddr.IPNetwork(self.flow_info[k].dst_ipaddr)
            dst_ip = str(_dst_ipaddr)

            self.mask_list_src = {}
            self.mask_list_dst = {}
            self.val = 0

            self.mask_list = self.calculate_port_mask(self.flow_info[k].src_port_min, self.flow_info[k].src_port_max, self.mask_list_src, self.val, 0)
            self.msk_list_src = self.mask_list
            self.mask_list = {}
            self.val = 0
            self.mask_list = self.calculate_port_mask(self.flow_info[k].dst_port_min, self.flow_info[k].dst_port_max, self.mask_list_dst, self.val, 0)
            self.mask_list_dst = self.mask_list
            self.mask_list = {}
            self.val = 0
            for l in self.mask_list_src.keys():
                for m in self.mask_list_dst.keys():
                    metadata = str((self.mask_list_src[l]['key'] << 16) + self.mask_list_dst[m]['key'])
                    metadata_mask = str((self.mask_list_src[l]['mask'] << 16) + self.mask_list_dst[m]['mask'])
                    mod_flow_entry(datapath,
                                   {'priority' : priority,
                                    'table_id' : 2,
                                    'match' : {'ipv4_src' : src_ip,
                                               'ipv4_dst' : dst_ip,
                                               'dl_type' : 2048,
                                               'ip_proto' : int(self.flow_info[k].ipproto),
                                               'metadata' : metadata + '/' + metadata_mask},
                                    'actions' : []},
                                   ofproto.OFPFC_ADD)


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
        elif pkt_tcp:
            src_port = pkt_tcp.src_port

        if pkt_udp:
            dst_port = pkt_udp.dst_port
        elif pkt_tcp:
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
                            'match' : {'tp_dst': src_port,
                                       'dl_type': 2048,
                                       'ip_proto': ipproto},
                            'actions' :[{'type' : 'WRITE_METADATA',
                                         'metadata': src_port,
                                         'metadata_mask': 65535},
                                        {'type' : 'GOTO_TABLE',
                                         'table_id' : 2}]},
                           ofproto.OFPFC_ADD)

            mod_flow_entry(datapath,
                           {'priority' : 100,
                            'table_id' : 0,
                            'match' : {'tp_src': dst_port,
                                       'dl_type': 2048,
                                       'ip_proto': ipproto},
                            'actions' :[{'type': 'WRITE_METADATA',
                                         'metadata': dst_port << 16,
                                         'metadata_mask': 4294901760},
                                        {'type': 'GOTO_TABLE',
                                         'table_id': 1}]},
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

    def calculate_port_mask(self, port_min, port_max, mask_list, val, length):
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

            mask_list[self.val] = {"key":port_min, "mask":tmp_mask}

            self.val = self.val + 1
            return 0

        if ((port_min & tmp_mask) == (port_max & tmp_mask)):
            self.calculate_port_mask(port_min, port_max, mask_list, val, length + 1)
        else:
            self.calculate_port_mask(port_min, (port_min | ~(tmp_mask)) & 65535, mask_list, val, length + 1)
            self.calculate_port_mask((port_max & (tmp_mask)), port_max, mask_list, val, length + 1)
            return mask_list

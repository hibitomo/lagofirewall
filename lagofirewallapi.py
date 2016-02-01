import logging

import json
import ast
from webob import Response

from ryu.app.ofctl_rest import StatsController
from ryu.app.ofctl_rest import RestStatsApi
from ryu.ofproto import ofproto_v1_3
from ryu.lib import ofctl_v1_3
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.app.wsgi import ControllerBase, WSGIApplication
from lagofirewall import Lago_Firewall

LOG = logging.getLogger('ryu.app.ofctl_rest')

supported_ofctl = {
    ofproto_v1_3.OFP_VERSION: ofctl_v1_3,
}

class LagoFwController(StatsController):
    def add_rule(self, req, dpid, **_kqargs):
        dp = self.dpset.get(int(dpid))
        ofproto = dp.ofproto
        if dp is None:
            return Response(status=404)
        try:
            rule = ast.literal_eval(req.body)
        except SyntaxError:
            LOG.debug('invalid syntax %s', req.body)
            return Response(status=400)
        Lago_Firewall.add_flow_rules(dp, ofproto, rule)

    def del_rule(self, req, dpid, **_kqargs):
        dp = self.dpset.get(int(dpid))
        ofproto = dp.ofproto
        if dp is None:
            return Response(status=404)
        try:
            rule = ast.literal_eval(req.body)
        except SyntaxError:
            LOG.debug('invalid syntax %s', req.body)
            return Response(status=400)
        Lago_Firewall.del_flow_rules(dp, ofproto, rule)


class RestLagoFwApi(RestStatsApi):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(RestStatsApi, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']
        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {}
        self.data['dpset'] = self.dpset
        self.data['waiters'] = self.waiters
        mapper = wsgi.mapper

        wsgi.registory['LagoFwController'] = self.data



        path = '/lagofw'
        uri = path + '/rule/{dpid}/add'
        mapper.connect('stats', uri,
                       controller=LagoFwController, action='add_rule',
                       conditions=dict(method=['POST']))

        path = '/lagofw'
        uri = path + '/rule/{dpid}/del'
        mapper.connect('stats', uri,
                       controller=LagoFwController, action='del_rule',
                       conditions=dict(method=['DELETE']))


        path = '/stats'
        uri = path + '/switches'
        mapper.connect('stats', uri,
                       controller=LagoFwController, action='get_dpids',
                       conditions=dict(method=['GET']))

        uri = path + '/desc/{dpid}'
        mapper.connect('stats', uri,
                       controller=LagoFwController, action='get_desc_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/flow/{dpid}'
        mapper.connect('stats', uri,
                       controller=LagoFwController, action='get_flow_stats',
                       conditions=dict(method=['GET', 'POST']))

        uri = path + '/aggregateflow/{dpid}'
        mapper.connect('stats', uri,
                       controller=LagoFwController,
                       action='get_aggregate_flow_stats',
                       conditions=dict(method=['GET', 'POST']))

        uri = path + '/port/{dpid}'
        mapper.connect('stats', uri,
                       controller=LagoFwController, action='get_port_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/queue/{dpid}'
        mapper.connect('stats', uri,
                       controller=LagoFwController, action='get_queue_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/meterfeatures/{dpid}'
        mapper.connect('stats', uri,
                       controller=LagoFwController, action='get_meter_features',
                       conditions=dict(method=['GET']))

        uri = path + '/meterconfig/{dpid}'
        mapper.connect('stats', uri,
                       controller=LagoFwController, action='get_meter_config',
                       conditions=dict(method=['GET']))

        uri = path + '/meter/{dpid}'
        mapper.connect('stats', uri,
                       controller=LagoFwController, action='get_meter_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/groupfeatures/{dpid}'
        mapper.connect('stats', uri,
                       controller=LagoFwController, action='get_group_features',
                       conditions=dict(method=['GET']))

        uri = path + '/groupdesc/{dpid}'
        mapper.connect('stats', uri,
                       controller=LagoFwController, action='get_group_desc',
                       conditions=dict(method=['GET']))

        uri = path + '/group/{dpid}'
        mapper.connect('stats', uri,
                       controller=LagoFwController, action='get_group_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/portdesc/{dpid}'
        mapper.connect('stats', uri,
                       controller=LagoFwController, action='get_port_desc',
                       conditions=dict(method=['GET']))

        uri = path + '/flowentry/{cmd}'
        mapper.connect('stats', uri,
                       controller=LagoFwController, action='mod_flow_entry',
                       conditions=dict(method=['POST']))

        uri = path + '/flowentry/clear/{dpid}'
        mapper.connect('stats', uri,
                       controller=LagoFwController, action='delete_flow_entry',
                       conditions=dict(method=['DELETE']))

        uri = path + '/meterentry/{cmd}'
        mapper.connect('stats', uri,
                       controller=LagoFwController, action='mod_meter_entry',
                       conditions=dict(method=['POST']))

        uri = path + '/groupentry/{cmd}'
        mapper.connect('stats', uri,
                       controller=LagoFwController, action='mod_group_entry',
                       conditions=dict(method=['POST']))

        uri = path + '/portdesc/{cmd}'
        mapper.connect('stats', uri,
                       controller=LagoFwController, action='mod_port_behavior',
                       conditions=dict(method=['POST']))

        uri = path + '/experimenter/{dpid}'
        mapper.connect('stats', uri,
                       controller=LagoFwController, action='send_experimenter',
                       conditions=dict(method=['POST']))


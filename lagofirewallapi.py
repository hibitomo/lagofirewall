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


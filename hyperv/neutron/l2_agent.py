# Copyright 2015 Cloudbase Solutions Srl
#
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import sys

from neutron.agent.common import config
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import config as common_config
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron import context as neutron_context
from neutron_lib import constants as n_const
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import loopingcall

from hyperv.common.i18n import _LE, _LI
from hyperv.neutron import constants as h_const
from hyperv.neutron import hyperv_neutron_agent

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


class HyperVSecurityAgent(sg_rpc.SecurityGroupAgentRpc):

    def __init__(self, context, plugin_rpc):
        super(HyperVSecurityAgent, self).__init__(context, plugin_rpc)
        if sg_rpc.is_firewall_enabled():
            self._setup_rpc()

    @property
    def use_enhanced_rpc(self):
        return True

    def _setup_rpc(self):
        self.topic = topics.AGENT
        self.endpoints = [HyperVSecurityCallbackMixin(self)]
        consumers = [[topics.SECURITY_GROUP, topics.UPDATE]]

        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     self.topic,
                                                     consumers)


class HyperVSecurityCallbackMixin(sg_rpc.SecurityGroupAgentRpcCallbackMixin):

    target = oslo_messaging.Target(version='1.3')

    def __init__(self, sg_agent):
        super(HyperVSecurityCallbackMixin, self).__init__()
        self.sg_agent = sg_agent


class HyperVNeutronAgent(hyperv_neutron_agent.HyperVNeutronAgent):

    # Set RPC API version to 1.1 by default.
    target = oslo_messaging.Target(version='1.1')

    def __init__(self):
        super(HyperVNeutronAgent, self).__init__(cfg.CONF)

    def _get_agent_configurations(self):
        """Get all the available configurations for the current agent."""
        conf = {h_const.VSWITCH_MAPPINGS: self._physical_network_mappings}
        if CONF.NVGRE.enable_support:
            conf[h_const.ARP_RESPONDER_ENABLED] = False
            conf[h_const.BRIDGE_MAPPINGS] = {}
            conf[h_const.DEVICES] = 1
            conf[h_const.ENABLE_DISTRIBUTED_ROUTING] = False
            conf[h_const.L2_POPUlATION] = False
            conf[h_const.TUNNELING_IP] = CONF.NVGRE.provider_tunnel_ip
            conf[h_const.TUNNEL_TYPES] = [h_const.TYPE_NVGRE]
        return conf

    def _set_agent_state(self):
        """Set the state for the current agent."""
        self._agent_state = {
            h_const.AGENT_TYPE: h_const.AGENT_TYPE_HYPERV,
            h_const.BINARY: 'neutron-hyperv-agent',
            h_const.CONDITIONS: self._get_agent_configurations(),
            h_const.HOST: CONF.host,
            h_const.TOPIC: n_const.L2_AGENT_TOPIC,
            h_const.START_FLAG: True,
        }

    def _report_state(self):
        try:
            self._state_rpc.report_state(self._context,
                                         self._agent_state)
            self._agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(_LE("Failed reporting state!"))

    def _setup_rpc(self):
        self._plugin_rpc = agent_rpc.PluginApi(topics.PLUGIN)
        self._sg_plugin_rpc = sg_rpc.SecurityGroupServerRpcApi(topics.PLUGIN)

        # RPC network init
        self._context = neutron_context.get_admin_context_without_session()
        self._sec_groups_agent = HyperVSecurityAgent(self._context,
                                                     self._sg_plugin_rpc)
        self._state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)

        # Handle updates from service
        self._endpoints = [self]
        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.DELETE],
                     [topics.PORT, topics.DELETE]]
        if CONF.NVGRE.enable_support:
            consumers.append([h_const.TUNNEL, topics.UPDATE])
            consumers.append([h_const.LOOKUP, h_const.UPDATE])

        self._connection = agent_rpc.create_consumers(self._endpoints,
                                                      self._topic,
                                                      consumers)

        self._client = n_rpc.get_client(self.target)
        report_interval = CONF.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)


def main():
    config.register_agent_state_opts_helper(cfg.CONF)
    common_config.init(sys.argv[1:])
    config.setup_logging()

    hyperv_agent = HyperVNeutronAgent()

    # Start everything.
    LOG.info(_LI("Agent initialized successfully, now running... "))
    hyperv_agent.daemon_loop()

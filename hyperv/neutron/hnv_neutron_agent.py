# Copyright 2016 Cloudbase Solutions SRL
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

"""This module contains all the available contract classes."""

# pylint: disable=invalid-name, unused-argument, protected-access

import platform
import sys

from neutron.agent.common import config as neutron_config
from neutron.common import config as common_config
from neutron_lib import constants as n_const
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging

from hyperv.common import i18n
from hyperv.neutron import _common_utils as c_util
from hyperv.neutron import base as hyperv_base
from hyperv.neutron import constants as h_const
from hyperv.neutron import neutron_client

LOG = logging.getLogger(__name__)
CONF = cfg.CONF
CONF.import_group('AGENT', 'hyperv.neutron.config')

_port_synchronized = c_util.get_port_synchronized_decorator('n-hnv-agent-')
_synchronized = lockutils.synchronized_with_prefix('n-hnv-agent-')


class HNVAgent(hyperv_base.Layer2Agent):

    target = oslo_messaging.Target(version='1.1')

    def __init__(self, config):
        super(HNVAgent, self).__init__(config)
        # Handle updates from service
        self._agent_id = 'hnv_%s' % platform.node()
        self._endpoints.append(self)
        self._neutron_client = neutron_client.NeutronAPIClient()

    def _provision_network(self, port_id, net_uuid, network_type,
                           physical_network, segmentation_id):
        """Provision the network with the received information."""
        LOG.info(i18n._LI("Provisioning network %s"), net_uuid)

        vswitch_name = self._get_vswitch_name(network_type, physical_network)
        vswitch_map = {
            'network_type': network_type,
            'vswitch_name': vswitch_name,
            'ports': [],
            'vlan_id': segmentation_id}
        self._network_vswitch_map[net_uuid] = vswitch_map

    def _set_agent_state(self):
        """Set the state for the agent."""
        self._agent_state.update({
            'binary': 'neutron-hnv-agent',
            'host': self._config.host,
            'configurations': {
                'logical_network': self._config.AGENT.logical_network,
                'vswitch_mappings': self._physical_network_mappings,
                'devices': 1,
                'l2_population': False,
                'tunnel_types': [],
                'bridge_mappings': {},
                'enable_distributed_routing': False,
            },
            'agent_type': h_const.AGENT_TYPE_HNV,
            'topic': n_const.L2_AGENT_TOPIC,
            'start_flag': True
        })

    def _port_bound(self, port_id, network_id, network_type, physical_network,
                    segmentation_id):
        """Bind the port to the recived network."""
        super(HNVAgent, self)._port_bound(port_id, network_id, network_type,
                                          physical_network, segmentation_id)
        LOG.debug("Getting the profile id for the current port.")
        profile_id = self._neutron_client.get_port_profile_id(port_id)

        LOG.debug("Trying to set port profile id %r for the current port %r.",
                  profile_id, port_id)
        self._utils.set_vswitch_port_profile_id(
            switch_port_name=port_id,
            profile_id=profile_id,
            profile_data=h_const.PROFILE_DATA,
            profile_name=h_const.PROFILE_NAME,
            net_cfg_instance_id=h_const.NET_CFG_INSTANCE_ID,
            cdn_label_id=h_const.CDN_LABEL_ID,
            cdn_label_string=h_const.CDN_LABEL_STRING,
            vendor_id=h_const.VENDOR_ID,
            vendor_name=h_const.VENDOR_NAME,
        )

    @_synchronized('n-plugin-notifier')
    def _notify_plugin_on_port_updates(self):
        super(HNVAgent, self)._notify_plugin_on_port_updates()

    @_port_synchronized
    def _treat_vif_port(self, port_id, network_id, network_type,
                        physical_network, segmentation_id,
                        admin_state_up):
        if admin_state_up:
            self._port_bound(port_id, network_id, network_type,
                             physical_network, segmentation_id)
        else:
            self._port_unbound(port_id)


def main():
    """The entry point for the HNV Agent."""
    neutron_config.register_agent_state_opts_helper(cfg.CONF)
    common_config.init(sys.argv[1:])
    neutron_config.setup_logging()

    hnv_agent = HNVAgent(cfg.CONF)

    # Start everything.
    LOG.info(i18n._LI("Agent initialized successfully, now running... "))
    hnv_agent.daemon_loop()

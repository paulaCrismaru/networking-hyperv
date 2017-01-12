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

import sys
import platform

import eventlet
from neutron.agent.common import config as neutron_config
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import config as common_config
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron import context as n_context
from neutron_lib import constants as n_const
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import loopingcall

from hyperv.common import base as h_base
from hyperv.common import i18n
from hyperv.neutron import constants as h_const
from hyperv.neutron import neutron_client

LOG = logging.getLogger(__name__)
CONF = cfg.CONF
CONF.import_group('AGENT', 'hyperv.neutron.config')


class _HNVSecurityCallbackMixin(sg_rpc.SecurityGroupAgentRpcCallbackMixin):

    target = oslo_messaging.Target(version='1.3')

    def __init__(self, sg_agent):
        super(_HNVSecurityCallbackMixin, self).__init__()
        self.sg_agent = sg_agent


class _HNVSecurityAgent(sg_rpc.SecurityGroupAgentRpc):

    def __init__(self, context, plugin_rpc):
        super(_HNVSecurityAgent, self).__init__(context, plugin_rpc)
        if sg_rpc.is_firewall_enabled():
            self._setup_rpc()

    @property
    def use_enhanced_rpc(self):
        return True

    def _setup_rpc(self):
        self.topic = topics.AGENT
        self.endpoints = [_HNVSecurityCallbackMixin(self)]
        consumers = [[topics.SECURITY_GROUP, topics.UPDATE]]

        self.connection = agent_rpc.create_consumers(
            self.endpoints, self.topic, consumers)


class HNVAgent(h_base.BaseAgent):

    target = oslo_messaging.Target(version='1.1')

    def __init__(self, config):
        super(HNVAgent, self).__init__(config)
        # Handle updates from service
        self._endpoints.append(self)
        self._neutron_client = neutron_client.NeutronAPIClient()

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

    def _setup_rpc(self):
        """Setup the RPC client for the current agent."""
        self._agent_id = 'hnv_%s' % platform.node()
        self._plugin_rpc = agent_rpc.PluginApi(topics.PLUGIN)
        # self._sg_plugin_rpc = sg_rpc.SecurityGroupServerRpcApi(topics.PLUGIN)

        # RPC network init
        self._context = n_context.get_admin_context_without_session()
        # self._sec_groups_agent = _HNVSecurityAgent(self._context,
        #                                            self._sg_plugin_rpc)
        self._state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)

        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.DELETE],
                     [topics.PORT, topics.DELETE]]

        self.connection = agent_rpc.create_consumers(
            self._endpoints, self._topic, consumers)

        self._client = n_rpc.get_client(self.target)
        report_interval = self._config.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)

    def _report_state(self):
        try:
            self._state_rpc.report_state(self._context,
                                         self._agent_state)
            self._agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(i18n._LE("Failed reporting state!"))

    def _reclaim_local_network(self, net_uuid):
        LOG.info(i18n._LI("Reclaiming local network %s"), net_uuid)
        del self._network_vswitch_map[net_uuid]

    def _update_port_status_cache(self, device, device_bound=True):
        """Update the ports status cache."""
        with self._cache_lock:
            if device_bound:
                self._bound_ports.add(device)
                self._unbound_ports.discard(device)
            else:
                self._bound_ports.discard(device)
                self._unbound_ports.add(device)

    def _process_added_port_event(self, port_name):
        """Callback for added ports."""
        LOG.info(i18n._LI("HNV VM vNIC added: %s"), port_name)
        self._added_ports.add(port_name)

    def _port_bound(self, port_id, network_id, network_type, physical_network,
                    segmentation_id):
        """Bind the port to the recived network."""
        LOG.debug("Binding port %s", port_id)

        if network_id not in self._network_vswitch_map:
            self._provision_network(
                port_id, network_id, network_type,
                physical_network, segmentation_id)

        vswitch_map = self._network_vswitch_map[network_id]
        vswitch_map['ports'].append(port_id)

        LOG.debug("Trying to connect the current port to vswitch %r.",
                  vswitch_map['vswitch_name'])
        self._utils.connect_vnic_to_vswitch(
            vswitch_name=vswitch_map['vswitch_name'],
            switch_port_name=port_id,
        )

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

    def _process_added_port(self, device_details):
        """Process the new ports."""
        device = device_details['device']
        try:
            if device_details['admin_state_up']:
                self._port_bound(
                    port_id=device_details['port_id'],
                    network_id=device_details['network_id'],
                    network_type=device_details['network_type'],
                    physical_network=device_details['physical_network'],
                    segmentation_id=device_details['segmentation_id'])

                LOG.debug("Updating cached port %s status as UP.",
                          device_details['port_id'])
                self._update_port_status_cache(device, device_bound=True)
                LOG.info("Port %s processed.", device_details['port_id'])
            else:
                self._port_unbound(device_details['port_id'])
        except Exception:
            LOG.exception(
                i18n._LE("Exception encountered while processing port %s."),
                device_details['port_id'])

            # Add the port as a new port in order to be reprocessed.
            self._added_ports.add(device)

    def _treat_devices_added(self):
        """Process the new devices."""
        try:
            devices_details_list = self._plugin_rpc.get_devices_details_list(
                self._context, self._added_ports, self._agent_id)
        except Exception as e:
            LOG.debug("Unable to get ports details for "
                      "devices %(devices)s: %(e)s",
                      {'devices': self._added_ports, 'e': e})
            return

        for device_details in devices_details_list:
            device = device_details['device']
            LOG.info(i18n._LI("Adding port %s"), device)
            if 'port_id' in device_details:
                LOG.info(i18n._LI("Port %(device)s updated. "
                                  "Details: %(device_details)s"),
                         {'device': device, 'device_details': device_details})
                eventlet.spawn_n(self._process_added_port, device_details)
            else:
                LOG.debug(i18n._("Missing port_id from device details: "
                                 "%(device)s. Details: %(device_details)s"),
                          {'device': device, 'device_details': device_details})

            LOG.debug(i18n._("Remove the port from added ports set, so it "
                             "doesn't get reprocessed."))
            self._added_ports.discard(device)

    def _port_unbound(self, port_id, vnic_deleted=False):
        LOG.debug(i18n._("Trying to unbind the port %r"), port_id)

        vswitch = self._get_network_vswitch_map_by_port_id(port_id)
        net_uuid, vswitch_map = vswitch

        if not net_uuid:
            LOG.debug('Port %s was not found on this agent.', port_id)
            return

        LOG.debug("Unbinding port %s", port_id)
        self._utils.remove_switch_port(port_id, vnic_deleted)
        vswitch_map['ports'].remove(port_id)

        if not vswitch_map['ports']:
            self._reclaim_local_network(net_uuid)

    def _process_removed_port(self, device):
        """Process the removed ports."""
        LOG.debug(i18n._("Trying to remove the port %r"), device)
        self._update_port_status_cache(device, device_bound=False)
        self._port_unbound(device, vnic_deleted=True)

        LOG.debug(i18n._("The port was successfully removed."))
        self._removed_ports.discard(device)

    def _process_removed_port_event(self, port_name):
        """Callback for removed ports."""
        LOG.info(i18n._LI("HNV VM vNIC removed: %s"), port_name)
        self._removed_ports.add(port_name)

    def _treat_devices_removed(self):
        """Process the removed devices."""
        for device in self._removed_ports.copy():
            eventlet.spawn_n(self._process_removed_port, device)

    def _work(self):
        """Process the information regarding the available ports."""
        eventlet.spawn_n(self._notify_plugin_on_port_updates)

        # notify plugin about port deltas
        if self._added_ports:
            LOG.debug("Agent loop has new devices!")
            self._treat_devices_added()

        if self._removed_ports:
            LOG.debug("Agent loop has lost devices...")
            self._treat_devices_removed()

    def port_delete(self, context, port_id=None):
        """Delete the received port."""
        LOG.debug("port_delete event received for %r", port_id)

    def port_update(self, context, port=None, network_type=None,
                    segmentation_id=None, physical_network=None):
        """Update the received port."""
        LOG.debug("port_update event received for %r", port['id'])

        if self._utils.vnic_port_exists(port['id']):
            if port['admin_state_up']:
                self._port_bound(
                    port_id=port['id'],
                    network_id=port['network_id'],
                    network_type=network_type,
                    physical_network=physical_network,
                    segmentation_id=segmentation_id)
            else:
                self._port_unbound(port['id'])
        else:
            LOG.debug("No port %s defined on agent.", port['id'])


def main():
    """The entry point for the HNV Agent."""
    neutron_config.register_agent_state_opts_helper(cfg.CONF)
    common_config.init(sys.argv[1:])
    neutron_config.setup_logging()

    hnv_agent = HNVAgent(cfg.CONF)

    # Start everything.
    LOG.info(i18n._LI("Agent initialized successfully, now running... "))
    hnv_agent.daemon_loop()

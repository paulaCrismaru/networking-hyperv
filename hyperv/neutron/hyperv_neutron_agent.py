# Copyright 2013 Cloudbase Solutions SRL
# Copyright 2013 Pedro Navarro Perez
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

# pylint: disable=invalid-name, unused-argument

import collections
import re

import eventlet
from eventlet import tpool
from os_win import exceptions
from os_win import utilsfactory
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging
import six
import threading

from hyperv.common import base as h_base
from hyperv.common.i18n import _, _LE, _LW, _LI  # noqa
from hyperv.neutron import _common_utils as c_util
from hyperv.neutron import constants
from hyperv.neutron import exception
from hyperv.neutron import nvgre_ops

CONF = cfg.CONF
CONF.import_group('NVGRE', 'hyperv.neutron.config')
LOG = logging.getLogger(__name__)

_port_synchronized = c_util.get_port_synchronized_decorator('n-hv-agent-')
synchronized = lockutils.synchronized_with_prefix('n-hv-agent-')


class HyperVNeutronAgent(h_base.BaseAgent):

    def __init__(self, conf=None):
        """Initializes local configuration of the Hyper-V Neutron Agent."""
        super(HyperVNeutronAgent, self).__init__(config=conf)
        self._cache_lock = threading.Lock()
        self._host = self._config.get('host', None)

        self._network_vswitch_map = {}
        self._port_metric_retries = {}

        self._metricsutils = utilsfactory.get_metricsutils()
        self._nvgre_ops = nvgre_ops.HyperVNvgreOps()

        agent_conf = self._config.get('AGENT', {})
        security_conf = self._config.get('SECURITYGROUP', {})
        self._local_network_vswitch = agent_conf.get('local_network_vswitch',
                                                     'private')
        self._worker_count = agent_conf.get('worker_count')
        self._phys_net_map = agent_conf.get(
            'physical_network_vswitch_mappings', [])
        self._enable_metrics_collection = agent_conf.get(
            'enable_metrics_collection', False)
        self._metrics_max_retries = agent_conf.get('metrics_max_retries', 100)

        self._enable_security_groups = security_conf.get(
            'enable_security_group', False)

        tpool.set_num_threads(self._worker_count)

        self._load_physical_network_mappings(self._phys_net_map)
        self._setup_operation_agents()

    def _get_vswitch_for_physical_network(self, phys_network_name):
        """Get the vswitch name for the received network name."""
        for pattern in self._physical_network_mappings:
            if phys_network_name is None:
                phys_network_name = ''
            if re.match(pattern, phys_network_name):
                return self._physical_network_mappings[pattern]
        # Not found in the mappings, the vswitch has the same name
        return phys_network_name

    def _get_network_vswitch_map_by_port_id(self, port_id):
        """Get the vswitch name for the received port id."""
        for network_id, vswitch in six.iteritems(self._network_vswitch_map):
            if port_id in vswitch['ports']:
                return (network_id, vswitch)

        # If the port was not found, just return (None, None)
        return (None, None)

    def _get_vswitch_name(self, network_type, physical_network):
        """Get the vswitch name for the received network information."""
        if network_type != constants.TYPE_LOCAL:
            vswitch_name = self._get_vswitch_for_physical_network(
                physical_network)
        else:
            vswitch_name = self._local_network_vswitch
        return vswitch_name

    def _load_physical_network_mappings(self, phys_net_vswitch_mappings):
        """Load all the information regarding the physical network."""
        self._physical_network_mappings = collections.OrderedDict()
        for mapping in phys_net_vswitch_mappings:
            parts = mapping.split(':')
            if len(parts) != 2:
                LOG.debug('Invalid physical network mapping: %s', mapping)
            else:
                pattern = re.escape(parts[0].strip()).replace('\\*', '.*')
                pattern = pattern + '$'
                vswitch = parts[1].strip()
                self._physical_network_mappings[pattern] = vswitch

    def _setup_operation_agents(self):
        """Setup all the available operations agents."""
        physical_networks = list(self._physical_network_mappings.values())
        if self._nvgre_ops.enabled:
            self._nvgre_ops.setup(physical_networks=physical_networks)
            self._nvgre_ops.init_notifier(self._context, self._client)
            self._nvgre_ops.tunnel_update(self._context,
                                          CONF.NVGRE.provider_tunnel_ip,
                                          constants.TYPE_NVGRE)

    def _provision_network(self, port_id, net_uuid, network_type,
                           physical_network, segmentation_id):
        """Provision the network with the received information."""
        LOG.info(_LI("Provisioning network %s"), net_uuid)

        vswitch_name = self._get_vswitch_name(network_type, physical_network)
        if network_type == constants.TYPE_VLAN:
            # Nothing to do
            pass
        elif network_type == constants.TYPE_NVGRE and self._nvgre_ops.enabled:
            self._nvgre_ops.bind_network(
                segmentation_id, net_uuid, vswitch_name)
        elif network_type == constants.TYPE_FLAT:
            # Nothing to do
            pass
        elif network_type == constants.TYPE_LOCAL:
            # TODO(alexpilotti): Check that the switch type is private
            # or create it if not existing
            pass
        else:
            raise exception.NetworkingHyperVException(
                (_("Cannot provision unknown network type %(network_type)s"
                   " for network %(net_uuid)s") %
                 dict(network_type=network_type, net_uuid=net_uuid)))

        vswitch_map = {
            'network_type': network_type,
            'vswitch_name': vswitch_name,
            'ports': [],
            'vlan_id': segmentation_id}
        self._network_vswitch_map[net_uuid] = vswitch_map

    def _reclaim_local_network(self, net_uuid):
        LOG.info(_LI("Reclaiming local network %s"), net_uuid)
        del self._network_vswitch_map[net_uuid]

    def _port_bound(self, port_id, net_uuid, network_type, physical_network,
                    segmentation_id):
        """Bind the port to the recived network."""
        LOG.debug("Binding port %s", port_id)

        if net_uuid not in self._network_vswitch_map:
            self._provision_network(
                port_id, net_uuid, network_type,
                physical_network, segmentation_id)

        vswitch_map = self._network_vswitch_map[net_uuid]
        vswitch_map['ports'].append(port_id)

        self._utils.connect_vnic_to_vswitch(vswitch_map['vswitch_name'],
                                            port_id)

        if network_type == constants.TYPE_VLAN:
            LOG.info(_LI('Binding VLAN ID %(segmentation_id)s '
                         'to switch port %(port_id)s'),
                     dict(segmentation_id=segmentation_id, port_id=port_id))
            self._utils.set_vswitch_port_vlan_id(
                segmentation_id,
                port_id)
        elif network_type == constants.TYPE_NVGRE and self._nvgre_ops.enabled:
            self._nvgre_ops.bind_port(
                segmentation_id, vswitch_map['vswitch_name'], port_id)
        elif network_type == constants.TYPE_FLAT:
            # Nothing to do
            pass
        elif network_type == constants.TYPE_LOCAL:
            # Nothing to do
            pass
        else:
            LOG.error(_LE('Unsupported network type %s'), network_type)

        if self._enable_metrics_collection:
            self._utils.add_metrics_collection_acls(port_id)
            self._port_metric_retries[port_id] = self._metrics_max_retries

    def _port_unbound(self, port_id, vnic_deleted=False):
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

    def _port_enable_control_metrics(self):
        if not self._enable_metrics_collection:
            return

        for port_id in list(self._port_metric_retries.keys()):
            try:
                if self._utils.is_metrics_collection_allowed(port_id):
                    self._metricsutils.enable_port_metrics_collection(port_id)
                    LOG.info(_LI('Port metrics enabled for port: %s'), port_id)
                    del self._port_metric_retries[port_id]
                elif self._port_metric_retries[port_id] < 1:
                    self._metricsutils.enable_port_metrics_collection(port_id)
                    LOG.error(_LE('Port metrics raw enabling for port: %s'),
                              port_id)
                    del self._port_metric_retries[port_id]
                else:
                    self._port_metric_retries[port_id] -= 1
            except exceptions.NotFound:
                # the vNIC no longer exists. it might have been removed or
                # the VM it was attached to was destroyed.
                LOG.warning(_LW("Port %s no longer exists. Cannot enable "
                                "metrics."), port_id)
                del self._port_metric_retries[port_id]

    @_port_synchronized
    def _treat_vif_port(self, port_id, network_id, network_type,
                        physical_network, segmentation_id,
                        admin_state_up):
        if admin_state_up:
            self._port_bound(port_id, network_id, network_type,
                             physical_network, segmentation_id)
            # check if security groups is enabled.
            # if not, teardown the security group rules
            if self._enable_security_groups:
                self._sec_groups_agent.refresh_firewall([port_id])
            else:
                self._utils.remove_all_security_rules(port_id)
        else:
            self._port_unbound(port_id)
            self._sec_groups_agent.remove_devices_filter([port_id])

    def _process_added_port(self, device_details):
        """Process the new ports."""
        device = device_details['device']
        port_id = device_details['port_id']

        try:
            self._treat_vif_port(port_id,
                                 device_details['network_id'],
                                 device_details['network_type'],
                                 device_details['physical_network'],
                                 device_details['segmentation_id'],
                                 device_details['admin_state_up'])

            LOG.debug("Updating cached port %s status as UP.", port_id)
            self._update_port_status_cache(device, device_bound=True)
            LOG.info("Port %s processed.", port_id)
        except Exception:
            LOG.exception(_LE("Exception encountered while processing port "
                              "%s."), port_id)

            # readd the port as "added", so it can be reprocessed.
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
            LOG.info(_LI("Adding port %s"), device)
            if 'port_id' in device_details:
                LOG.info(_LI("Port %(device)s updated. Details: "
                             "%(device_details)s"),
                         {'device': device, 'device_details': device_details})

                eventlet.spawn_n(self._process_added_port, device_details)

            # remove the port from added ports set, so it doesn't get
            # reprocessed.
            self._added_ports.discard(device)

    def _treat_devices_removed(self):
        """Process the removed devices."""
        for device in self._removed_ports.copy():
            eventlet.spawn_n(self._process_removed_port, device)

    def _process_removed_port(self, device):
        """Process the removed ports."""
        self._update_port_status_cache(device, device_bound=False)

        self._port_unbound(device, vnic_deleted=True)
        self._sec_groups_agent.remove_devices_filter([device])

        # if the port unbind was successful, remove the port from removed
        # set, so it won't be reprocessed.
        self._removed_ports.discard(device)

    def _process_added_port_event(self, port_name):
        """Callback for added ports."""
        LOG.info(_LI("Hyper-V VM vNIC added: %s"), port_name)
        self._added_ports.add(port_name)

    def _process_removed_port_event(self, port_name):
        """Callback for removed ports."""
        LOG.info(_LI("Hyper-V VM vNIC removed: %s"), port_name)
        self._removed_ports.add(port_name)

    def _update_port_status_cache(self, device, device_bound=True):
        """Update the ports status cache."""
        with self._cache_lock:
            if device_bound:
                self._bound_ports.add(device)
                self._unbound_ports.discard(device)
            else:
                self._bound_ports.discard(device)
                self._unbound_ports.add(device)

    @synchronized('n-plugin-notifier')
    def _notify_plugin_on_port_updates(self):
        if not (self._bound_ports or self._unbound_ports):
            return

        with self._cache_lock:
            bound_ports = self._bound_ports.copy()
            unbound_ports = self._unbound_ports.copy()

        self._plugin_rpc.update_device_list(self._context,
                                            list(bound_ports),
                                            list(unbound_ports),
                                            self._agent_id,
                                            self._host)

        with self._cache_lock:
            self._bound_ports = self._bound_ports.difference(bound_ports)
            self._unbound_ports = self._unbound_ports.difference(
                unbound_ports)

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

        if self._nvgre_ops.enabled:
            self._nvgre_ops.refresh_records()

        self._port_enable_control_metrics()

    def network_delete(self, context, network_id=None):
        """Delete the received network."""
        LOG.debug("network_delete received. "
                  "Deleting network %s", network_id)
        # The network may not be defined on this agent
        if network_id in self._network_vswitch_map:
            self._reclaim_local_network(network_id)
        else:
            LOG.debug("Network %s not defined on agent.", network_id)

    def port_delete(self, context, port_id=None):
        """Delete the received port."""
        pass

    def port_update(self, context, port=None, network_type=None,
                    segmentation_id=None, physical_network=None):
        """Update the information for the received port."""
        LOG.debug("port_update received: %s", port['id'])

        if self._utils.vnic_port_exists(port['id']):
            self._treat_vif_port(
                port['id'], port['network_id'],
                network_type, physical_network,
                segmentation_id, port['admin_state_up'])
        else:
            LOG.debug("No port %s defined on agent.", port['id'])

    def tunnel_update(self, context, **kwargs):
        """Update the information for the tunnel."""
        LOG.info(_LI('tunnel_update received: kwargs: %s'), kwargs)
        tunnel_ip = kwargs.get('tunnel_ip')
        if tunnel_ip == CONF.NVGRE.provider_tunnel_ip:
            # the notification should be ignored if it originates from this
            # node.
            return

        tunnel_type = kwargs.get('tunnel_type')
        self._nvgre_ops.tunnel_update(self._context, tunnel_ip, tunnel_type)

    def lookup_update(self, context, **kwargs):
        self._nvgre_ops.lookup_update(kwargs)

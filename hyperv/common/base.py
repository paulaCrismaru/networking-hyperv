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


import abc
import collections
import re
import threading
import time

import eventlet
from neutron.common import topics
from os_win import utilsfactory
from oslo_concurrency import lockutils
from oslo_log import log as logging
import six

from hyperv.common import i18n
from hyperv.neutron import constants

LOG = logging.getLogger(__name__)

_synchronized = lockutils.synchronized_with_prefix('n-hnv-agent-')


@six.add_metaclass(abc.ABCMeta)
class BaseAgent(object):

    """Contact class for all the neutron agents."""

    def __init__(self, config):
        """Initializes local configuration of the current agent.

        :param conf: dict or dict-like object containing the configuration
                     details used by this Agent. If None is specified, default
                     values are used instead.
        """
        self._agent_id = None
        self._topic = topics.AGENT
        self._config = config or {}
        self._cache_lock = threading.Lock()
        self._host = self._config.get('host', None)

        self._context = None
        self._client = None
        self._network_vswitch_map = {}

        # The following sets contain ports that are to be processed.
        self._added_ports = set()
        self._removed_ports = set()

        # The following sets contain ports that have been processed.
        self._bound_ports = set()
        self._unbound_ports = set()

        self._utils = utilsfactory.get_networkutils()
        self._utils.init_caches()

        # The following attributes will be initialized by the
        # `_setup_rpc` method.
        self._client = None
        self._connection = None
        self._endpoints = []
        self._context = None
        self._plugin_rpc = None
        self._sg_plugin_rpc = None
        self._sec_groups_agent = None
        self._state_rpc = None
        self._agent_state = {}
        self._physical_network_mappings = {}

        agent_config = config.get("AGENT", {})
        self._polling_interval = agent_config.get('polling_interval', 2)
        self._phys_net_map = agent_config.get(
            'physical_network_vswitch_mappings', [])
        self._local_network_vswitch = agent_config.get(
            'local_network_vswitch', 'private')

        self._load_physical_network_mappings(self._phys_net_map)
        self._setup_rpc()
        self._set_agent_state()

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

    def _get_network_vswitch_map_by_port_id(self, port_id):
        """Get the vswitch name for the received port id."""
        for network_id, vswitch in six.iteritems(self._network_vswitch_map):
            if port_id in vswitch['ports']:
                return (network_id, vswitch)

        # If the port was not found, just return (None, None)
        return (None, None)

    def _get_vswitch_for_physical_network(self, phys_network_name):
        """Get the vswitch name for the received network name."""
        for pattern in self._physical_network_mappings:
            if phys_network_name is None:
                phys_network_name = ''
            if re.match(pattern, phys_network_name):
                return self._physical_network_mappings[pattern]
        # Not found in the mappings, the vswitch has the same name
        return phys_network_name

    def _get_vswitch_name(self, network_type, physical_network):
        """Get the vswitch name for the received network information."""
        if network_type != constants.TYPE_LOCAL:
            vswitch_name = self._get_vswitch_for_physical_network(
                physical_network)
        else:
            vswitch_name = self._local_network_vswitch
        return vswitch_name

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

    @abc.abstractmethod
    def _process_added_port_event(self, port_name):
        """Callback for port added event."""
        pass

    @abc.abstractmethod
    def _process_removed_port_event(self, port_name):
        """Callback for port removed event."""
        pass

    @abc.abstractmethod
    def _set_agent_state(self):
        """Set the state for the agent."""
        pass

    @abc.abstractmethod
    def _setup_rpc(self):
        """Setup the RPC client for the current agent."""
        pass

    @abc.abstractmethod
    def _work(self):
        """Override this with your desired procedures."""
        pass

    def _create_event_listeners(self):
        """Create and bind the event listeners."""
        LOG.debug("Create the event listeners.")
        event_callback_pairs = [
            (self._utils.EVENT_TYPE_CREATE, self._process_added_port_event),
            (self._utils.EVENT_TYPE_DELETE, self._process_removed_port_event)]

        for event_type, callback in event_callback_pairs:
            LOG.debug("Create listener for %r event", event_type)
            listener = self._utils.get_vnic_event_listener(event_type)
            eventlet.spawn_n(listener, callback)

    @_synchronized('n-plugin-notifier')
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

    def daemon_loop(self):
        """Process all the available ports."""
        self._added_ports = self._utils.get_vnic_ids()
        self._create_event_listeners()
        while True:
            start = time.time()
            try:
                self._work()
            except Exception:
                LOG.exception(i18n._LE("Error in agent event loop"))
                # Inconsistent cache might cause exceptions. for example, if a
                # port has been removed, it will be known in the next loop.
                # using the old switch port can cause exceptions.
                self._utils.update_cache()

            # Sleep until the end of polling interval
            elapsed = (time.time() - start)
            if elapsed < self._polling_interval:
                time.sleep(self._polling_interval - elapsed)
            else:
                LOG.debug("Loop iteration exceeded interval "
                          "(%(polling_interval)s vs. %(elapsed)s)",
                          {'polling_interval': self._polling_interval,
                           'elapsed': elapsed})

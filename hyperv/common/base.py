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

# TODO(alexcoman): Provide documentation for each parameter.

import abc
import platform
import time

import eventlet
from neutron.common import topics
from os_win import utilsfactory
from oslo_log import log as logging
import six

from hyperv.common import i18n
from hyperv.neutron import constants
from hyperv.neutron import neutron_client

LOG = logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class BaseAgent(object):

    """Contact class for all the neutron agents."""

    def __init__(self, config):
        """Initializes local configuration of the current agent.

        :param conf: dict or dict-like object containing the configuration
                     details used by this Agent. If None is specified, default
                     values are used instead.

        ..note::
            The conf schema is as follows:
                {
                    'host': string,
                    'AGENT': {
                        'polling_interval': int,
                        'local_network_vswitch': string,
                        'physical_network_vswitch_mappings': array,
                        'enable_metrics_collection': boolean,
                        'metrics_max_retries': int
                    },
                    'SECURITYGROUP': {
                        'enable_security_group': boolean
                    }
                }

            For more information on the arguments, their meaning and their
            default values, visit: https://goo.gl/FK5FsT
        """
        self._agent_id = 'hyperv_%s' % platform.node()
        self._topic = topics.AGENT
        self._config = config or {}
        self._polling_interval = self._config .get('polling_interval', 2)

        self._context = None
        self._client = None

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
        self._endpoints = None
        self._context = None
        self._plugin_rpc = None
        self._sg_plugin_rpc = None
        self._sec_groups_agent = None
        self._state_rpc = None

        self._setup_rpc()
        self._set_agent_state()

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
        event_callback_pairs = [
            (self._utils.EVENT_TYPE_CREATE, self._process_added_port_event),
            (self._utils.EVENT_TYPE_DELETE, self._process_removed_port_event)]

        for event_type, callback in event_callback_pairs:
            listener = self._utils.get_vnic_event_listener(event_type)
            eventlet.spawn_n(listener, callback)

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


@six.add_metaclass(abc.ABCMeta)
class Operations(object):

    """Contact class for all the objects that expose operations."""

    def __init__(self):
        self._neutron_client = neutron_client.NeutronAPIClient()
        self._enabled = False
        self._ports = []
        self._topic = constants.AGENT_TOPIC

    @property
    def enabled(self):
        """Whether the operations are available nor not."""
        return self._enabled

    @abc.abstractmethod
    def setup(self, physical_networks):
        """Setup the current operations provider.

        :param physical_networks:
        """
        pass

    @abc.abstractmethod
    def bind_port(self, segmentation_id, network_name, port_id):
        """Bind the port to the required network.

        :param segmentation_id:
        :param network_name:
        :param port_id:
        """
        pass

    @abc.abstractmethod
    def bind_network(self, segmentation_id, net_uuid, vswitch_name):
        """Bind the network to the required switch.

        :param segmentation_id:
        :param net_uuid:
        :param vswitch_name:
        """
        pass

    @abc.abstractmethod
    def refresh_records(self, net_uuid=None):
        """Update the information regarding the unprocessed ports.

        :param net_uuid:
        """
        pass

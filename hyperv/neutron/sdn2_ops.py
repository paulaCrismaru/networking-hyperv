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

"""A basic interface for the SDN API."""

from os_win import utilsfactory
from oslo_config import cfg
from oslo_log import log as logging

from hyperv.neutron import constants
from hyperv.neutron import hyperv_agent_notifier
from hyperv.neutron import neutron_client


CONF = cfg.CONF
CONF.import_group('SDN2', 'hyperv.neutron.config')
LOG = logging.getLogger(__name__)


class SDN2Ops(object):

    """Operations available for interaction with SDN.

    Software Defined Networking (SDN) provides a method to centrally
    configure and manage physical and virtual network devices such as
    routers, switches, and gateways in a datacenter.
    """

    def __init__(self, physical_networks):
        self._context = None
        self._notifier = None
        self._topic = constants.AGENT_TOPIC

        self._hyperv_utils = utilsfactory.get_networkutils()
        self._neutron = neutron_client.NeutronAPIClient()

        self._init(physical_networks)

    def _init(self, physical_networks):
        """Setup the SDN 2.0 Agent."""
        for network in physical_networks:
            # TODO(alexcoman): Create provider route
            # TODO(alexcoman): Create provider address
            pass

    def init_notifier(self, context, rpc_client):
        """Setup the RPC client in order to interact with OpenStack API."""
        self._context = context
        self._notifier = hyperv_agent_notifier.AgentNotifierApi(
            self._topic, rpc_client)

    def refresh_records(self, **kwargs):
        """Update the information regarding the unprocessed ports."""
        pass

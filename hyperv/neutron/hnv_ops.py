# Copyright 2017 Cloudbase Solutions Srl
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

from oslo_config import cfg
from oslo_log import log as logging

from hyperv.neutron import exception
from hyperv.neutron import hnv_client

CONF = cfg.CONF
CONF.import_group('SDN2', 'hyperv.neutron.config')
LOG = logging.getLogger(__name__)

DISABLED = "disabled"
ENABLED = "enabled"
STATIC = "static"


class HNVOperations(object):

    def __init__(self):
        pass

    def bind_port(self, port_id, network_id, network_type, physical_network,
                  segmentation_id, mac_address):
        # Note(alexcoman): More details regarding this operations can be found
        # on the following article "Create a VM and Connect to a Tenant
        # Virtual Network or VLAN" (https://goo.gl/mMRb4X).

        # Get the Virtual Network that contains the subnet to which you want
        # to connect the network adapter.
        try:
            virtual_network = hnv_client.VirtualNetworks.get(
                resource_id=network_id, parent_id=None)
        except exception.NotFound:
            LOG.debug("The required VirtualNetwork doesn't exists.")
            raise

        # Get the logical network subnet
        logical_network = hnv_client.LogicalNetworks.get(
            resource_id=physical_network)
        if not logical_network.subnetworks:
            message = ("No logical subnetwork available for %s" %
                       logical_network.resource_id)
            LOG.debug(message)
            raise exception.ServiceException(message)

        subnetwork = logical_network.subnetworks[0]

        # Create a ip configuration object for the NetworkInterface
        ip_configuration = hnv_client.IPConfiguration(
            # FIXME(alexcoman): Change with a valid IP address.
            private_ip_address="127.0.0.1",
            private_ip_allocation_method=STATIC,
            subnet=hnv_client.Resource(resource_ref=subnetwork.resource_ref)
        )

        # Prepare the DNS settings for the new network inferface
        dns_settings = {"DnsServers": subnetwork.dns_servers}

        # Create a port settings object for the NetworkInterface
        port_settings = hnv_client.PortSettings(
            mac_spoofing=DISABLED,  # Allows the virtual machine to use only
                                    # the MAC address assigned to it
            arp_guard=DISABLED,     # Allows ARP to pass through the port
            dhcp_guard=DISABLED,    # Allows the message to be received
            storm_limit=0,          # No limit
            port_flow_limit=0,      # No limit
        )

        # Create a network interface object in Network Controller.
        network_interface = hnv_client.NetworkInterfaces(
            ip_configurations=ip_configuration,
            is_host=True,
            is_primary=True,
            internal_dns_name=None,
            port_settings=port_settings,
            mac_address=mac_address,
            mac_allocation_method=STATIC,
            dns_settings=dns_settings,
        ).commit()

        # Get the InstanceId for the network interface from
        # the Network Controller.
        instance_id = network_interface.resource_id

        # TODO(alexcoman): Set the port profile ID.

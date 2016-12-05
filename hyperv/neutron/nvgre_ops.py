# Copyright 2015 Cloudbase Solutions SRL
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

from os_win import utilsfactory
from oslo_config import cfg
from oslo_log import log as logging
import six
import uuid

from hyperv.common.i18n import _, _LI, _LW, _LE  # noqa
from hyperv.common import base as hyperv_base
from hyperv.neutron import constants
from hyperv.neutron import exception
from hyperv.neutron import hyperv_agent_notifier

CONF = cfg.CONF
CONF.import_group('AGENT', 'hyperv.neutron.config')
CONF.import_group('NVGRE', 'hyperv.neutron.config')

LOG = logging.getLogger(__name__)


class HyperVNvgreOps(hyperv_base.Operations):

    def __init__(self):
        super(HyperVNvgreOps, self).__init__()
        self._enabled = CONF.NVGRE.enable_support

        self._context = None
        self._notifier = None

        self._vswitch_ips = {}
        self._tunneling_agents = {}
        self._nvgre_ports = []
        self._network_vsids = {}

        self._hyperv_utils = utilsfactory.get_networkutils()
        self._utils = utilsfactory.get_nvgreutils()

    def setup(self, physical_networks):
        """Setup the current operations provider."""
        if not self.enabled:
            return

        if not CONF.NVGRE.provider_tunnel_ip:
            err_msg = _('enable_nvgre_support is set to True, but provider '
                        'tunnel IP is not configured. Check neutron.conf '
                        'config file.')
            LOG.error(err_msg)
            raise exception.NetworkingHyperVException(err_msg)

        for network in physical_networks:
            LOG.info(_LI("Adding provider route and address for network: %s"),
                     network)
            self._utils.create_provider_route(network)
            self._utils.create_provider_address(
                network, CONF.NVGRE.provider_vlan_id)
            ip_address, length = self._utils.get_network_iface_ip(network)
            self._vswitch_ips[network] = ip_address

    def _refresh_tunneling_agents(self):
        self._tunneling_agents.update(
            self._neutron_client.get_tunneling_agents())

    def _register_lookup_record(self, prov_addr, cust_addr, mac_addr, vsid):
        LOG.info(_LI('Creating LookupRecord: VSID: %(vsid)s MAC: %(mac_addr)s '
                     'Customer IP: %(cust_addr)s Provider IP: %(prov_addr)s'),
                 dict(vsid=vsid,
                      mac_addr=mac_addr,
                      cust_addr=cust_addr,
                      prov_addr=prov_addr))

        self._utils.create_lookup_record(
            prov_addr, cust_addr, mac_addr, vsid)

    def _create_customer_routes(self, segmentation_id, cidr, gw, rdid_uuid):
        self._utils.clear_customer_routes(segmentation_id)

        # create cidr -> 0.0.0.0/0 customer route
        self._utils.create_customer_route(
            segmentation_id, cidr, constants.IPV4_DEFAULT, rdid_uuid)

        if not gw:
            LOG.info(_LI('Subnet does not have gateway configured. '
                         'Skipping.'))
        elif gw.split('.')[-1] == '1':
            LOG.error(_LE('Subnet has unsupported gateway IP ending in 1: '
                          '%s. Any other gateway IP is supported.'), gw)
        else:
            # create 0.0.0.0/0 -> gateway customer route
            self._utils.create_customer_route(
                segmentation_id, '%s/0' % constants.IPV4_DEFAULT, gw,
                rdid_uuid)

            # create metadata address -> gateway customer route
            metadata_addr = '%s/32' % CONF.AGENT.neutron_metadata_address
            self._utils.create_customer_route(
                segmentation_id, metadata_addr, gw, rdid_uuid)

    def init_notifier(self, context, rpc_client):
        self._context = context
        self._notifier = hyperv_agent_notifier.AgentNotifierApi(
            self._topic, rpc_client)

    def lookup_update(self, kwargs):
        lookup_ip = kwargs.get('lookup_ip')
        lookup_details = kwargs.get('lookup_details')

        LOG.info(_LI("Lookup Received: %(lookup_ip)s, %(lookup_details)s"),
                 {'lookup_ip': lookup_ip, 'lookup_details': lookup_details})
        if not lookup_ip or not lookup_details:
            return

        self._register_lookup_record(lookup_ip,
                                     lookup_details['customer_addr'],
                                     lookup_details['mac_addr'],
                                     lookup_details['customer_vsid'])

    def bind_port(self, segmentation_id, network_name, port_id):
        """Bind the port to the required network."""
        mac_addr = self._hyperv_utils.get_vnic_mac_address(port_id)
        provider_addr = self._utils.get_network_iface_ip(network_name)[0]
        customer_addr = self._neutron_client.get_port_ip_address(port_id)

        if not provider_addr or not customer_addr:
            LOG.warning(_LW('Cannot bind NVGRE port. Could not determine '
                            'provider address (%(prov_addr)s) or customer '
                            'address (%(cust_addr)s).'),
                        {'prov_addr': provider_addr,
                         'cust_addr': customer_addr})
            return

        LOG.info(_LI('Binding VirtualSubnetID %(segmentation_id)s '
                     'to switch port %(port_id)s'),
                 dict(segmentation_id=segmentation_id, port_id=port_id))
        self._hyperv_utils.set_vswitch_port_vsid(segmentation_id, port_id)

        # normal lookup record.
        self._register_lookup_record(
            provider_addr, customer_addr, mac_addr, segmentation_id)

        # lookup record for dhcp requests.
        self._register_lookup_record(
            self._vswitch_ips[network_name], constants.IPV4_DEFAULT,
            mac_addr, segmentation_id)

        LOG.info('Fanning out LookupRecord...')
        self._notifier.lookup_update(self._context,
                                     provider_addr,
                                     {'customer_addr': customer_addr,
                                      'mac_addr': mac_addr,
                                      'customer_vsid': segmentation_id})

    def bind_network(self, segmentation_id, net_uuid, vswitch_name):
        """Bind the network to the required switch."""
        subnets = self._neutron_client.get_network_subnets(net_uuid)
        if len(subnets) > 1:
            LOG.warning(_LW("Multiple subnets in the same network is not "
                            "supported."))
        subnet = subnets[0]
        try:
            cidr, gw = (self._neutron_client
                        .get_network_subnet_cidr_and_gateway(subnet))
            cust_route_string = vswitch_name + cidr + str(segmentation_id)
            rdid_uuid = str(uuid.uuid5(uuid.NAMESPACE_X500, cust_route_string))
            self._create_customer_routes(segmentation_id, cidr, gw, rdid_uuid)

        except Exception as ex:
            LOG.error(_LE("Exception caught: %s"), ex)

        self._network_vsids[net_uuid] = segmentation_id
        self.refresh_records(network_id=net_uuid)
        self._notifier.tunnel_update(
            self._context, CONF.NVGRE.provider_tunnel_ip, segmentation_id)

    def refresh_records(self, net_uuid=None):
        """Update the information regarding the unprocessed ports."""
        self._refresh_tunneling_agents()
        ports = self._neutron_client.get_network_ports(net_uuid=net_uuid)

        # process ports that were not processed yet.
        # process ports that are bound to tunneling_agents.
        ports = [p for p in ports if p['id'] not in self._nvgre_ports and
                 p['binding:host_id'] in self._tunneling_agents and
                 p['network_id'] in six.iterkeys(self._network_vsids)]

        for port in ports:
            tunneling_ip = self._tunneling_agents[port['binding:host_id']]
            customer_addr = port['fixed_ips'][0]['ip_address']
            mac_addr = port['mac_address'].replace(':', '')
            segmentation_id = self._network_vsids[port['network_id']]
            try:
                self._register_lookup_record(
                    tunneling_ip, customer_addr, mac_addr, segmentation_id)

                self._nvgre_ports.append(port['id'])
            except Exception as ex:
                LOG.error(_LE("Exception while adding lookup_record: %(ex)s. "
                              "VSID: %(vsid)s MAC: %(mac_address)s Customer "
                              "IP:%(cust_addr)s Provider IP: %(prov_addr)s"),
                          dict(ex=ex,
                               vsid=segmentation_id,
                               mac_address=mac_addr,
                               cust_addr=customer_addr,
                               prov_addr=tunneling_ip))

    def tunnel_update(self, context, tunnel_ip, tunnel_type):
        if tunnel_type != constants.TYPE_NVGRE:
            return
        self._notifier.tunnel_update(context, CONF.NVGRE.provider_tunnel_ip,
                                     tunnel_type)

# Copyright 2016 Cloudbase Solutions Srl
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

import uuid

from oslo_config import cfg
from oslo_log import log as logging
import requests

from hyperv.common import objects
from hyperv.neutron import exception

CONF = cfg.CONF
CONF.import_group('SDN2', 'hyperv.neutron.config')
LOG = logging.getLogger(__name__)


class _BaseClient(object):

    def __init__(self, url=CONF.SDN2.url, username=CONF.SDN2.username,
                 password=CONF.SDN2.password):
        self._base_url = url
        self._credentials = requests.auth.HTTPDigestAuth(username, password)
        self._https_allow_insecure = CONF.SDN2.https_allow_insecure
        self._https_ca_bundle = CONF.SDN2.https_ca_bundle

    @staticmethod
    def _get_headers():
        """Prepare the HTTP headers for the current request."""

        # TODO(alexcoman): Add the x-ms-client-ip-address header in order
        # to improve the Network Controller requests logging.
        return {
            "Accept": "application/json",
            "Content-Type": "application/json; charset=UTF-8",
            "x-ms-client-request-id": uuid.uuid1().hex,
            "x-ms-return-client-request-id": "1",
        }

    def _verify_https_request(self):
        """Whether to disable the validation of HTTPS certificates.

        .. notes::
            When `https_allow_insecure` option is `True` the SSL certificate
            validation for the connection with the Network Controller API will
            be disabled (please don't use it if you don't know the
            implications of this behaviour).
        """
        if self._https_ca_bundle:
            return self._https_ca_bundle
        else:
            return self._https_allow_insecure

    def _http_request(self, resource, method="GET", body=None):
        url = requests.compat.urljoin(self._base_url, resource)
        response = requests.request(method=method, url=url, data=body,
                                    headers=self._get_headers(),
                                    auth=self._credentials,
                                    verify=self._verify_https_request())

        if response.status_code == 404:
            raise exception.NotFound("Resource %r was not found." % resource)
        response.raise_for_status()

        try:
            return response.json()
        except ValueError:
            raise exception.ServiceException("Invalid service response.")

    def get_resource(self, path):
        """Getting the required information from the API."""
        try:
            response = self._http_request(path)
        except requests.exceptions.SSLError as exc:
            LOG.error(exc)
            raise exception.CertificateVerifyFailed(
                "HTTPS certificate validation failed.")

        return response

    def update_resource(self, path, data):
        """Update the required resource."""
        try:
            response = self._http_request(path, method="PUT", body=data)
        except requests.exceptions.SSLError as exc:
            LOG.error(exc)
            raise exception.CertificateVerifyFailed(
                "HTTPS certificate validation failed.")

        return response

    def remove_resource(self, path):
        """Delete the received resource."""
        try:
            self._http_request(path, method="DELETE")
        except requests.exceptions.SSLError as exc:
            LOG.error(exc)
            raise exception.CertificateVerifyFailed(
                "HTTPS certificate validation failed.")


class _ConfigurationState(objects.Model):

    """Model for configuration state."""

    uuid = objects.Field(name="id")
    status = objects.Field(name="status")
    last_update = objects.Field(name="lastUpdatedTime")
    interface_errors = objects.Field(name="virtualNetworkInterfaceErrors")
    host_errors = objects.Field(name="hostErrors")


class _VirtualInterfaceError(objects.Model):

    """Model for Virtual interface errors."""

    uuid = objects.Field(name="id")
    status = objects.Field(name="status")
    details = objects.Field(name="detailedInfo")
    last_update = objects.Field(name="lastUpdatedTime")


class _BaseSDNModel(objects.Model):

    _client = _BaseClient()
    _endpoint = CONF.SDN2.url

    resource_ref = objects.Field(name="resourceRef")
    """A relative URI to an associated resource."""

    resource_id = objects.Field(name="resourceId")
    """The resource ID for the resource. The value MUST be unique in
    the context of the resource if it is a top-level resource, or in the
    context of the direct parent resource if it is a child resource."""

    etag = objects.Field(name="etag")
    """An opaque string representing the state of the resource at the
    time the response was generated."""

    instance_id = objects.Field(name="instanceId")
    """The globally unique Id generated and used internally by the Network
    Controller. The mapping resource that enables the client to map between
    the instanceId and the resourceId."""

    @staticmethod
    def _get_fields(raw_data):
        """Process the API response."""
        if "properties" not in raw_data:
            return raw_data

        properties = raw_data.pop("properties", {})
        for key, value in properties:
            raw_data[key] = value

        return raw_data

    @classmethod
    def get(cls, resource_id=None, parent_id=None):
        """Retrieves the required resources.

        :param resource_id:      The identifier for the specific resource
                                 within the resource type.
        :param parent_id:        The identifier for the specific ancestor
                                 resource within the resource type.
        """

        endpoint = cls._endpoint.format(resource_id=resource_id,
                                        parent_id=parent_id)
        raw_data = cls._client.get_resource(endpoint)
        if resource_id is None:
            return [cls(**cls._get_fields(subnet))
                    for subnet in raw_data["value"]]
        else:
            return cls(**cls._get_fields(raw_data))

    @classmethod
    def remove(cls, resource_id, parent_id):
        """Delete the required resource.

        :param resource_id:      The identifier for the specific resource
                                 within the resource type.
        :param parent_id:        The identifier for the specific ancestor
                                 resource within the resource type.
        """
        pass

    def set(self):
        """Update (or create) the resource."""
        pass

    def commit(self):
        """Apply all the changes on the current model."""
        super(_BaseSDNModel, self).commit()
        self.set()


class _IPConfiguration(_BaseSDNModel):

    """IP Configuration Model.

    This resource represents configuration information for IP addresses:
    allocation method, actual IP address, membership of a logical or virtual
    subnet, load balancing and access control information.
    """

    provisioning_state = objects.Field(name="provisioningState")
    """Indicates the various states of the resource. Valid values are
    Deleting, Failed, Succeeded, and Updating."""

    private_ip_address = objects.Field(name="privateIPAddress")
    private_ip_address_method = objects.Field(name="privateIPAllocationMethod")
    subnet = objects.Field(name="subnet")
    access_controll_list = objects.Field(name="accessControlList")
    address_pools = objects.Field(name="loadBalancerBackendAddressPools")


class ACLRules(_BaseSDNModel):

    """ACL Rules Model.

    The aclRules resource describes the network traffic that is allowed
    or denied for a network interface of a virtual machine. Currently,
    only inbound rules are expressed.
    """

    provisioning_state = objects.Field(name="provisioningState")
    """Indicates the various states of the resource. Valid values are
    Deleting, Failed, Succeeded, and Updating."""

    action = objects.Field(name="action")
    """Indicates the action the ACL Rule will take. Valid values
    are: `Allow` and `Deny`."""

    destination_prefix = objects.Field(name="destinationAddressPrefix")
    """Indicates the CIDR value of destination IP or a pre-defined tag
    to which traffic is destined. You can specify 0.0.0.0/0 for IPv4
    all and ::/0 for IPv6 all traffic."""

    destination_port_range = objects.Field(name="destinationPortRange")
    """Indicates the destination port(s) that will trigger this ACL
    rule. Valid values include a single port, port range (separated by "-"),
    or "*" for all ports. All numbers are inclusive."""

    source_prefix = objects.Field(name="sourceAddressPrefix")
    """Indicates the CIDR value of source IP or a pre-defined TAG from
    which traffic is originating. You can specify 0.0.0.0/0 for IPv4 all
    and ::/0 forIPv6 all traffic."""

    source_port_range = objects.Field(name="sourcePortRange")
    """Indicates the source port(s) that will trigger this ACL rule.
    Valid values include a single port, port range (separated by "-"),
    or "*" for all ports. All numbers are inclusive."""

    description = objects.Field(name="description")
    """Indicates a description of the ACL rule."""

    logging = objects.Field(name="logging", default="Enabled")
    """Indicates whether logging will be turned on for when this
    rule gets triggered. Valid values are `Enabled` or `Disabled`."""

    priority = objects.Field(name="priority")
    """Indicates the priority of the rule relative to the priority of
    other ACL rules. This is a unique numeric value in the context of
    an accessControlLists resource. Value from 101 - 65000 are user
    defined. Values 1 - 100 and 65001 - 65535 are reserved."""

    protocol = objects.Field(name="protocol")
    """Indicates the protocol to which the ACL rule will apply.
    Valid values are `TCP` or `UDP`."""

    rule_type = objects.Field(name="type")
    """Indicates whether the rule is to be evaluated against ingress
    traffic (Inbound) or egress traffic (Outbound). Valid values are
    `Inbound` or `Outbound`."""


class AccessControlLists(_BaseSDNModel):

    """Access Constrol List Model.

    An accessControlLists resource contains a list of ACL rules.
    Access control list resources can be assigned to virtual subnets
    or IP configurations.

    An ACL can be associated with:
        * Subnets of a virtual or logical network. This means that all
        network interfaces (NICs) with IP configurations created in the
        subnet inherit the ACL rules in the Access Control List. Often,
        subnets are used for a specific architectural tier (frontend,
        middle tier, backend) in more complex applications. Assigning
        an ACL to subnets can thus be used to control the network flow
        between the different tiers.
        *IP configuration of a NIC. This means that the ACL will be
        applied to the parent network interface of the specified IP
        configuration.
    """

    acl_rules = objects.Field(name="aclRules")
    """Indicates the rules in an access control list."""

    inbound_action = objects.Field(name="inboundDefaultAction",
                                   default="Permit")
    """Indicates the default action for Inbound Rules. Valid values are
    `Permit` and `Deny`. The default value is `Permit`."""

    outbound_action = objects.Field(name="outboundDefaultAction",
                                    default="Permit")
    """Indicates the default action for Outbound Rules. Valid values are
    `Permit` and `Deny`. The default value is `Permit`."""

    ip_configuration = objects.Field(name="ipConfigurations")
    """Indicates references to IP addresses of network interfaces
    resources this access control list is associated with."""

    subnets = objects.Field(name="subnets")
    """Indicates an array of references to subnets resources this access
    control list is associated with."""


class SubNetwork(_BaseSDNModel):

    """SubNetwork Model.

    The subnets resource is used to create Virtual Subnets (VSIDs) under
    a tenant's virtual network (RDID). The user can specify the addressPrefix
    to use for the subnets, the accessControl Lists to protect the subnets,
    the routeTable to be applied to the subnet, and optionally the service
    insertion to use within the subnet.
    """

    _endpoint = requests.compat.urljoin(
        CONF.SDN2.url,
        "networking/v1/virtualNetworks/{parent_id}/subnets/{resource_id}")

    provisioning_state = objects.Field(name="provisioningState")
    """Indicates the various states of the resource. Valid values are
    Deleting, Failed, Succeeded, and Updating."""

    address_prefix = objects.Field(name="addressPrefix")
    """Indicates the address prefix that defines the subnet. The value is
    in the format of 0.0.0.0/0. This value must not overlap with other
    subnets in the virtual network and must fall in the addressPrefix defined
    in the virtual network."""

    access_controll_list = objects.Field(name="accessControlList")
    """Indicates a reference to an accessControlLists resource that defines
    the ACLs in and out of the subnet."""

    service_insertion = objects.Field(name="serviceInsertion")
    """Indicates a reference to a serviceInsertions resource that defines the
    service insertion to be applied to the subnet."""

    route_table = objects.Field(name="routeTable")
    """Indicates a reference to a routeTable resource that defines the tenant
    routes to be applied to the subnet."""

    ip_configuration = objects.Field(name="ipConfigurations")
    """Indicates an array of references of networkInterfaces resources that
    are connected to the subnet."""

    def set(self):
        """Creates a new subnet resource or updates an existing one."""
        endpoint = self._endpoint.format(resource_id=self.resource_id)
        request_body = {"properties": {"addressPrefix": self.address_prefix}}
        properties = request_body["properties"]

        if self.access_controll_list:
            properties["accessControlList"] = self.access_controll_list
        if self.service_insertion:
            properties["serviceInsertion"] = self.service_insertion
        if self.route_table:
            properties["routeTable"] = self.route_table

        self._client.update_resource(endpoint, data=request_body)

    @classmethod
    def remove(cls, resource_id, parent_id):
        """Delete the required resource.

        :param resource_id:      The identifier for the specific resource
                                 within the resource type.
        :param parent_id:        The identifier for the specific ancestor
                                 resource within the resource type.
        """
        endpoint = cls._endpoint.format(resource_id=resource_id,
                                        parent_id=parent_id)
        cls._client.remove_resource(endpoint)


class VirtualNetwork(_BaseSDNModel):

    """Virtual Network Model.

    This resource is used to create a virtual network using HNV for tenant
    overlays. The default encapsulation for virtualNetworks is Virtual
    Extensible LAN but this can be changed by updating the virtual
    NetworkManager resource. Similarly, the HNV Distributed Router is enabled
    by default but this can be overridden using the virtualNetworkManager
    resource.
    """

    provisioning_state = objects.Field(name="provisioningState")
    """Indicates the various states of the resource. Valid values are
    Deleting, Failed, Succeeded, and Updating."""

    configuration_state = objects.Field(name="configurationState")
    """Indicates the last known running state of this resource."""

    address_space = objects.Field(name="addressSpace")
    """Indicates the address space of the virtual network."""

    dhcp_options = objects.Field(name="dhcpOptions")
    """Indicates the DHCP options used by servers in the virtual
    network."""

    subnetworks = objects.Field(name="subnets")
    """Indicates the subnets that are on the virtual network."""

    logical_network = objects.Field(name="logicalNetwork")
    """Indicates a reference to the networks resource that is the
    underlay network which the virtual network runs on."""

    def set(self):
        """Create or update a virtual network using HNV for tenant overlays.

        The default encapsulation for virtualNetworks is Virtual Extensible
        LAN but this can be changed by updating the virtualNetworkManager
        resource. Similarly, the HNV Distributed Router is enabled by default
        but this can be overridden using the virtualNetworkManager resource.
        """
        endpoint = self._endpoint.format(resource_id=self.resource_id)
        request_body = {"properties": {
            "addressSpace": self.address_space,
            "logicalNetwork": self.logical_network,
        }}
        if self.subnetworks:
            request_body["properties"]["subnets"] = self.subnetworks
        if self.dhcp_options:
            request_body["properties"]["dhcp_options"] = self.dhcp_options

        self._client.update_resource(endpoint, data=request_body)


class MacPool(_BaseSDNModel):

    """MacPool Model.

    The macPools resource specifies a range of MAC addresses which are used
    internally by the Network Controller service modules and are plumbed down
    to the hosts for items such as Host vNICs.
    """

    provisioning_state = objects.Field(name="provisioningState")
    """Indicates the various states of the resource. Valid values are
    Deleting, Failed, Succeeded, and Updating."""

    start_mac_address = objects.Field(name="startMacAddress")
    end_mac_address = objects.Field(name="endMacAddress")
    addresses = objects.Field(name="numberOfMacAddresses")
    allocated_addresses = objects.Field(name="numberofMacAddressesAllocated")


class NetworkInterfaces(_BaseSDNModel):

    """Network Interface Model.

    The networkInterfaces resource specifies the configuration of either
    a host virtual interface (host vNIC) or a virtual server NIC (VMNIC).
    """

    provisioning_state = objects.Field(name="provisioningState")
    """Indicates the various states of the resource. Valid values are
    Deleting, Failed, Succeeded, and Updating."""

    dns_settings = objects.Field(name="dnsSettings")
    """Indicates the DNS settings of this network interface."""

    ip_configurations = objects.Field(name="ipConfigurations")
    """Indicates an array of IP configurations that are contained
    in the network interface."""

    is_host = objects.Field(name="isHostVirtualNetworkInterface")
    """True if this is a host virtual interface (host vNIC)
    False if this is a virtual server NIC (VMNIC)."""

    is_primary = objects.Field(name="isPrimary", default=True)
    """`True` if this is the primary interface and the default
    value if the property is not set or `False` if this is a
    secondary interface."""

    is_multitenant_stack = objects.Field(name="isMultitenantStack",
                                         default=False)
    """`True` if allows the NIC to be part of multiple virtual networks
    or `False` if the opposite."""

    internal_dns_name = objects.Field(name="internalDnsNameLabel")
    """Determines the name that will be registered in iDNS
    when the iDnsServer resource is configured."""

    server = objects.Field(name="server")
    """Indicates a reference to the servers resource for the
    machine that is currently hosting the virtual machine to
    which this network interface belongs."""

    port_settings = objects.Field(name="portSettings")
    """A PortSettings object."""

    mac_address = objects.Field(name="privateMacAddress")
    """Indicates the private MAC address of this network interface."""

    mac_allocation_method = objects.Field(name="privateMacAllocationMethod")
    """Indicates the allocation scheme of the MAC for this
    network interface."""

    service_insertion_elements = objects.Field(name="serviceInsertionElements")
    """Indicates an array of serviceInsertions resources that
    this networkInterfaces resource is part of."""


class PortSettings(_BaseSDNModel):

    mac_spoofing = objects.Field(name="macSpoofing")
    """Specifies whether virtual machines can change the source MAC
    address in outgoing packets to one not assigned to them."""

    arp_guard = objects.Field(name="arpGuard")
    """Specifies whether ARP guard is enabled or not. ARP guard
    will allow only addresses specified in ArpFilter to pass through
    the port."""

    dhcp_guard = objects.Field(name="dhcpGuard")
    """Specifies the number of broadcast, multicast, and unknown
    unicast packets per second a virtual machine is allowed to
    send through the specified virtual network adapter."""

    storm_limit = objects.Field(name="stormLimit")
    """Specifies the number of broadcast, multicast, and unknown
    unicast packets per second a virtual machine is allowed to
    send through the specified virtual network adapter."""

    port_flow_limit = objects.Field(name="portFlowLimit")
    """Specifies the maximum number of flows that can be executed
    for the port."""

    vmq_weight = objects.Field(name="vmqWeight")
    """Specifies whether virtual machine queue (VMQ) is to be
    enabled on the virtual network adapter."""

    iov_weight = objects.Field(name="iovWeight")
    """Specifies whether single-root I/O virtualization (SR-IOV) is to
    be enabled on this virtual network adapter."""

    iov_interrupt_moderation = objects.Field(name="iovInterruptModeration")
    """Specifies the interrupt moderation value for a single-root I/O
    virtualization (SR-IOV) virtual function assigned to a virtual
    network adapter."""

    iov_queue_pairs = objects.Field(name="iovQueuePairsRequested")
    """Specifies the number of hardware queue pairs to be allocated
    to an SR-IOV virtual function."""

    outbound_reserved_value = objects.Field(name="outboundReservedValue")
    """If outboundReservedMode is "absolute" then the value indicates the
    bandwidth, in Mbps, guaranteed to the virtual port for transmission
    (egress)."""

    outbound_maximum_mbps = objects.Field(name="QosSettings")
    """Indicates the maximum permitted send-side bandwidth, in Mbps,
    for the virtual port (egress)."""

    inbound_maximum_mbps = objects.Field(name="QosSettings")
    """Indicates the maximum permitted receive-side bandwidth for the
    virtual port (ingress) in Mbps."""

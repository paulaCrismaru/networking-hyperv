# Copyright 2013 Cloudbase Solutions SRL
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

# Topic for tunnel notifications between the plugin and agent
AGENT_TOPIC = 'q-agent-notifier'
AGENT_TYPE_HYPERV = 'HyperV agent'
VIF_TYPE_HYPERV = 'hyperv'

TUNNEL = 'tunnel'
LOOKUP = 'lookup'

UPDATE = 'update'

# Special vlan_id value in ovs_vlan_allocations table indicating flat network
FLAT_VLAN_ID = -1

TYPE_FLAT = 'flat'
TYPE_LOCAL = 'local'
TYPE_VLAN = 'vlan'
TYPE_NVGRE = 'gre'
TYPE_SDN2 = 'sdn2'  # FIXME(alexcoman): This value must be changed.

IPV4_DEFAULT = '0.0.0.0'

# Keys for agent state
AGENT_TYPE = "agent_type"
BINARY = "binary"
CONDITIONS = "configurations"
HOST = "host"
TOPIC = "topic"
START_FLAG = "start_flag"

# Keys for the agent configurations
ARP_RESPONDER_ENABLED = "arp_responder_enabled"
BRIDGE_MAPPINGS = "bridge_mappings"
DEVICES = "devices"
ENABLE_DISTRIBUTED_ROUTING = "enable_distributed_routing"
L2_POPUlATION = "l2_population"
VSWITCH_MAPPINGS = "vswitch_mappings"
TUNNELING_IP = "tunneling_ip"
TUNNEL_TYPES = "tunnel_types"

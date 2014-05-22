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

import sys
import uuid
import os
import simplejson as json

from heat.engine.clients import OpenStackClients
from heat.common.context import RequestContext
from heat.common.template_format import convert_json_to_yaml

from heat.engine.resources.server import Server as NovaServer
from heat.engine.resources.nova_keypair import KeyPair as NovaKeyPair
from heat.engine.resources.neutron.net import Net as NeutronNet
from heat.engine.resources.neutron.subnet import Subnet as NeutronSubnet
from heat.engine.resources.neutron.port import Port as NeutronPort
from heat.engine.resources.neutron.router import Router as NeutronRouter
from heat.engine.resources.neutron.router import RouterInterface as \
    NeutronRouterInterface
from heat.engine.resources.neutron.router import RouterGateway as \
    NeutronRouterGateway
from heat.engine.resources.neutron.security_group import SecurityGroup as \
    NeutronSecGroup
from heat.engine.resources.neutron.floatingip import FloatingIP as NeutronFIP

from heat.openstack.common import log as logging

logger = logging.getLogger(__name__)


class Template(object):
    def __init__(self, resources):
        self.resources = resources

    def get_json(self):
        res = {}
        for k, v in self.resources.iteritems():
            snippet = v.get_template()
            res[k] = v.resolve_refs(snippet, self.resources.keys())
        return {
            'resources': res,
        }

    def get_yaml(self):
        yaml = convert_json_to_yaml(json.dumps(self.get_json()))
        yaml = yaml.replace("""HeatTemplateFormatVersion: '2012-12-12'""",
                            """heat_template_version: '2013-05-23'""")
        return yaml


class Resource(object):

    def __init__(self, info, rtype):
        self.info = info
        self.type = rtype

    def get_properties(self):
        return {}

    def get_template(self):
        return {
            'type': self.type,
            'properties': self.get_properties()
        }

    def get_id(self):
        return self.info.get('id')

    def _fix_json(self, check_fun, mod_fun, json):
        if isinstance(json, dict):
            d = {}
            for k, v in json.items():
                w = self._fix_json(check_fun, mod_fun, v)
                if check_fun(k, w):
                    d[k] = w
            return d
        if isinstance(json, list):
            l = []
            for v in json:
                w = self._fix_json(check_fun, mod_fun, v)
                if w:
                    l.append(w)
            return l

        return mod_fun(json)

    def _mod_fun(self, json):
        return json

    def _check_fun(self, k, v):
        return True

    def _filter_nulls(self, json):
        def is_null(_, v):
            if isinstance(v, bool) or v:
                return True
            return False
        return self._fix_json(is_null, self._mod_fun, json)

    def _filter_prohibited_keys(self, json, keys):
        def is_allowed(k, _):
            return k in keys
        return self._fix_json(is_allowed, self._mod_fun, json)

    def apply_filters(self, json):
        json = self._filter_nulls(json)
        return json

    def resolve_refs(self, json, resources_ref_id):
        def replace_id(val):
            if isinstance(val, basestring) and val in resources_ref_id \
                    and val != self.get_id():
                return {'get_resource': val}
            return val
        return self._fix_json(self._check_fun, replace_id, json)


class Server(Resource):

    def __init__(self, info, snapshot_servers):
        super(Server, self).__init__(info, 'OS::Nova::Server')
        self.snapshot_servers = snapshot_servers

    def get_properties(self):
        logger.debug(('Getting template for Nova Server [%s]' %
                      self.info['id']))

        flavor_id = self.info['flavor']['id']
        flavor_name = clients.nova().flavors.get(flavor_id).name

        fixed_ip = None
        for net, addrs in self.info['addresses'].iteritems():
            for addr in addrs:
                if addr['OS-EXT-IPS:type'] == 'fixed':
                    fixed_ip = addr['addr']
                    break

        networks = []
        if fixed_ip is not None:
            for port in clients.neutron().list_ports()['ports']:
                if port.get('device_owner') == 'compute:None':
                    addrs = map(lambda fix: fix.get('ip_address'),
                                port.get('fixed_ips', []))
                    if fixed_ip in addrs:
                        networks.append({NovaServer.NETWORK_PORT: port['id']})
                        break

        if self.snapshot_servers:
            snapshot_name = self.info['name'] + "-" + str(uuid.uuid4())[:5]
            clients.nova().servers.create_image(self.info['id'], snapshot_name)
        else:
            image_id = self.info['image']['id']
            snapshot_name = clients.nova().images.get(image_id).name

        snippet = {
            NovaServer.NAME: self.info['name'],
            NovaServer.IMAGE: snapshot_name,
            NovaServer.FLAVOR: flavor_name,
            NovaServer.KEY_NAME: self.info['key_name'],
            NovaServer.AVAILABILITY_ZONE: self.info['OS-EXT-AZ:availability_zone'],
            NovaServer.NETWORKS: networks,
        }
        return self.apply_filters(snippet)


class KeyPair(Resource):

    def __init__(self, info):
        super(KeyPair, self).__init__(info, 'OS::Nova::KeyPair')

    def get_id(self):
        return self.info.get('name')

    def get_properties(self):
        logger.debug(('Getting template for Nova KeyPair [%s]' %
                      self.info['name']))

        snippet = {
            NovaKeyPair.NAME: self.info['name'],
            NovaKeyPair.PUBLIC_KEY: self.info['public_key'].replace('\n', ' ')
        }
        return self.apply_filters(snippet)


class Net(Resource):

    def __init__(self, info):
        super(Net, self).__init__(info, 'OS::Neutron::Net')

    def get_properties(self):
        logger.debug(('Getting template for Neutron Net [%s]' % self.info['id']))

        snippet = {
            NeutronNet.NAME: self.info['name'],
        }
        return self.apply_filters(snippet)


class Subnet(Resource):

    def __init__(self, info):
        super(Subnet, self).__init__(info, 'OS::Neutron::Subnet')

    def get_properties(self):
        logger.debug(('Getting template for Neutron Subnet [%s]' % self.info['id']))

        snippet = {
            NeutronSubnet.NAME: self.info['name'],
            NeutronSubnet.NETWORK_ID: self.info['network_id'],
            NeutronSubnet.DNS_NAMESERVERS: self.info['dns_nameservers'],
            NeutronSubnet.ALLOCATION_POOLS: self.info['allocation_pools'],
            NeutronSubnet.GATEWAY_IP: self.info['gateway_ip'],
            NeutronSubnet.CIDR: self.info['cidr'],
            NeutronSubnet.HOST_ROUTES: self.info['host_routes'],
            NeutronSubnet.ENABLE_DHCP: False,
        }
        return self.apply_filters(snippet)


class Port(Resource):

    def __init__(self, info):
        super(Port, self).__init__(info, 'OS::Neutron::Port')

    def get_properties(self):
        logger.debug(('Getting template for Neutron Port [%s]' % self.info['id']))

        snippet = {
            NeutronPort.NAME: self.info['name'],
            NeutronPort.NETWORK_ID: self.info['network_id'],
            NeutronPort.ALLOWED_ADDRESS_PAIRS: self.info['allowed_address_pairs'],
            NeutronPort.FIXED_IPS: self.info['fixed_ips'],
            NeutronPort.SECURITY_GROUPS: self.info['security_groups'],
        }

        return self.apply_filters(snippet)


class Router(Resource):

    def __init__(self, info):
        super(Router, self).__init__(info, 'OS::Neutron::Router')

    def get_properties(self):
        logger.debug(('Getting template for Neutron Router [%s]' % self.info['id']))

        snippet = {
            NeutronRouter.NAME: self.info['name'],
        }
        return self.apply_filters(snippet)


class RouterInterface(Resource):

    def __init__(self, info):
        super(RouterInterface, self).__init__(info,
                                              'OS::Neutron::RouterInterface')

    def get_id(self):
        return self.info.get('device_id') + '-' + (self.info.get('network_id') or '')[:8]

    def get_properties(self):
        logger.debug(('Getting template for Neutron Router Interface [%s]' % self.info['id']))

        snippet = {
            NeutronRouterInterface.ROUTER_ID: self.info['device_id'],
            NeutronRouterInterface.PORT_ID: self.info['id'],
        }
        return self.apply_filters(snippet)


class RouterGateway(Resource):

    def __init__(self, info):
        super(RouterGateway, self).__init__(info, 'OS::Neutron::RouterGateway')

    def get_id(self):
        return self.info.get('id') + '-' + (self.get_network_id() or '')[:8]

    def get_network_id(self):
        if NeutronRouter.EXTERNAL_GATEWAY in self.info:
            gateway = self.info[NeutronRouter.EXTERNAL_GATEWAY]
            if gateway and 'network_id' in gateway:
                return gateway['network_id']
        return None

    def get_properties(self):
        logger.debug(('Getting template for Neutron Router Gateway [%s]' %
                      self.info['id']))

        snippet = {
            NeutronRouterGateway.ROUTER_ID: self.info['id'],
            NeutronRouterGateway.NETWORK_ID: self.get_network_id(),
        }
        return self.apply_filters(snippet)


class FloatingIP(Resource):

    def __init__(self, info):
        super(FloatingIP, self).__init__(info, 'OS::Neutron::FloatingIP')

    def get_properties(self):
        logger.debug(('Getting template for Neutron FloatingIP [%s]' %
                      self.info['id']))

        snippet = {
            NeutronFIP.FLOATING_NETWORK_ID: self.info['floating_network_id'],
            NeutronFIP.PORT_ID: self.info['port_id'],
        }
        return self.apply_filters(snippet)


class SecurityGroups(Resource):

    def __init__(self, info):
        super(SecurityGroups, self).__init__(info, 'OS::Neutron::SecurityGroup')

    def apply_filters(self, json):
        json = super(SecurityGroups, self).apply_filters(json)
        json[NeutronSecGroup.RULES] = self._filter_prohibited_keys(
            json[NeutronSecGroup.RULES], NeutronSecGroup._RULE_KEYS)
        return json

    def get_properties(self):
        logger.debug(('Getting template for Neutron SecurityGroup [%s]' %
                      self.info['id']))

        snippet = {
            NeutronSecGroup.NAME: self.info['name'],
            NeutronSecGroup.DESCRIPTION: self.info['description'],
            NeutronSecGroup.RULES: self.info['security_group_rules'],
        }
        return self.apply_filters(snippet)


def init(cnxt):
    global clients
    clients = OpenStackClients(cnxt)

    existing_resources = []
    for server in clients.nova().servers.list():
        existing_resources.append(server.id)
    for keypair in clients.nova().keypairs.list():
        existing_resources.append(keypair.id)
    for net in clients.neutron().list_networks()['networks']:
        existing_resources.append(net['id'])
    for subnet in clients.neutron().list_subnets()['subnets']:
        existing_resources.append(subnet['id'])
    for router in clients.neutron().list_routers()['routers']:
        existing_resources.append(router['id'])
    for port in clients.neutron().list_ports()['ports']:
        existing_resources.append(port['id'])
    for floating_ip in clients.neutron().list_floatingips()['floatingips']:
        existing_resources.append(floating_ip['id'])
    for sec_group in clients.neutron().list_security_groups()['security_groups']:
        existing_resources.append(sec_group['id'])
    return existing_resources


def dump(cnxt, existing_resources, snapshot_servers=False):
    global clients
    clients = OpenStackClients(cnxt)
    resources = discover_existing_resources(existing_resources,
                                            snapshot_servers)
    template = Template(resources)
    return template.get_yaml()


def discover_existing_resources(existing_resources, snapshot_servers):
    def is_new(resource):
        if not isinstance(resource, dict):
            resource = resource.to_dict()
        return resource['id'] not in existing_resources

    resources = {}
    for server in clients.nova().servers.list():
        resources[server.id] = Server(server.to_dict(), snapshot_servers)

    for keypair in clients.nova().keypairs.list():
        resources[keypair.id] = KeyPair(keypair.to_dict()['keypair'])

    for net in clients.neutron().list_networks()['networks']:
        resources[net['id']] = Net(net)

    for subnet in clients.neutron().list_subnets()['subnets']:
        resources[subnet['id']] = Subnet(subnet)

    for router in filter(is_new, clients.neutron().list_routers()['routers']):
        resources[router['id']] = Router(router)
        gateway = RouterGateway(router)
        network_id = gateway.get_properties().get(
            NeutronRouterGateway.NETWORK_ID)
        if network_id:
            resources[gateway.get_id()] = gateway

    for port in filter(is_new, clients.neutron().list_ports()['ports']):
        device_owner = port.get('device_owner')
        if device_owner is not None:
            if device_owner == 'network:dhcp':
                continue
            if device_owner == 'network:router_interface':
                resources[port['id']] = Port(port)
                interface = RouterInterface(port)
                resources[interface.get_id()] = RouterInterface(port)
            if device_owner == 'compute:None':
                resources[port['id']] = Port(port)

    for floating_ip in clients.neutron().list_floatingips()['floatingips']:
        resources[floating_ip['id']] = FloatingIP(floating_ip)

    for sec_group in clients.neutron().list_security_groups()['security_groups']:
        resources[sec_group['id']] = SecurityGroups(sec_group)

    for id in existing_resources:
        if id in resources:
            del resources[id]

    return resources

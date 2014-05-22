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

from webob import exc

from heat.api.openstack.v1 import util
from heat.common import serializers
from heat.common import wsgi
from heat.rpc import client as rpc_client


class DiscoveryController(object):
    """
    WSGI controller for discovery in Heat v1 API
    Implements the API actions
    """

    REQUEST_SCOPE = 'discovery'

    def __init__(self, options):
        self.options = options
        self.rpc_client = rpc_client.EngineClient()

    def default(self, req, **args):
        raise exc.HTTPNotFound()

    @util.policy_enforce
    def init(self, req):
        """
        Discover init state
        """
        self.rpc_client.init_discovery(req.context)

    @util.policy_enforce
    def dump(self, req, body):
        """
        Discover existing resources and dependencies
        """
        server_snapshot = body.get('create_server_snapshot', False)
        template = self.rpc_client.dump_discovery(req.context, server_snapshot)
        return {'template': template}


def create_resource(options):
    """
    Discovery resource factory method.
    """
    deserializer = wsgi.JSONRequestDeserializer()
    serializer = serializers.JSONResponseSerializer()
    return wsgi.Resource(
        DiscoveryController(options), deserializer, serializer)

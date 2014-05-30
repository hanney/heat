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


class TemplateCatalgoueController(object):
    """
    WSGI controller for template catalogue in Heat v1 API
    Implements the API actions
    """

    REQUEST_SCOPE = 'template_catalogue'

    def __init__(self, options):
        self.options = options
        self.rpc_client = rpc_client.EngineClient()

    def default(self, req, **args):
        raise exc.HTTPNotFound()

    @util.policy_enforce
    def index(self, req):
        """
        List template catalogue entries.
        """
        tcs = self.rpc_client.list_template_catalogue(req.context)
        return {'template_catalogues': tcs}

    @util.policy_enforce
    def show(self, req, template_catalogue_id):
        """
        Gets detailed information for a template catalogue entry
        """
        tc = self.rpc_client.show_template_catalogue(req.context,
                                                     template_catalogue_id)
        return {'template_catalogue': tc}

    @util.policy_enforce
    def add(self, req, body):
        """
        Adds a new template catalogue entry
        """
        tc_data = dict((k, body.get(k)) for k in ('name', 'preview',
                                                  'template', 'public'))

        tc = self.rpc_client.add_template_catalogue(req.context, **tc_data)
        return {'template_catalogue': tc}

    @util.policy_enforce
    def delete(self, req, template_catalogue_id):
        """
        Delete an existing template catalogue entry
        """
        res = self.rpc_client.delete_template_catalogue(req.context,
                                                        template_catalogue_id)

        if res is not None:
            raise exc.HTTPBadRequest(res['Error'])

        raise exc.HTTPNoContent()


def create_resource(options):
    """
    TemplateCatalogue resource factory method.
    """
    deserializer = wsgi.JSONRequestDeserializer()
    serializer = serializers.JSONResponseSerializer()
    return wsgi.Resource(
        TemplateCatalgoueController(options), deserializer, serializer)

# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

from requests import exceptions

from heat.common.context import RequestContext
from heat.common import exception
from heat.common import heat_keystoneclient as hkc
from heat.common import template_format
from heat.common import urlfetch
from heat.engine import function
from heat.engine import properties
from heat.engine.properties import Properties
from heat.engine import resource

from heatclient import exc as heat_exp

from heat.openstack.common import log as logging

logger = logging.getLogger(__name__)

try:
    from heatclient import client as heatclient
except ImportError:
    heatclient = None
    logger.info(_('heatclient not available'))


class RemoteNestedStack(resource.Resource):
    """
    A Resource representing a stack which can be creating using specified
    context.
    """

    PROPERTIES = (
        CONTEXT, TEMPLATE_URL, TIMEOUT_IN_MINS, PARAMETERS,
    ) = (
        'context', 'template_url', 'timeout_in_minutes', 'parameters',
    )

    _CONTEXT_KEYS = (
        USERNAME, PASSWORD, TENANT_NAME, REGION_NAME
    ) = (
        'username', 'password', 'tenant_name', 'region_name',
    )

    properties_schema = {
        CONTEXT: properties.Schema(
            properties.Schema.MAP,
            _('Context for the stack.'),
            schema={
                USERNAME: properties.Schema(
                    properties.Schema.STRING,
                    _('Username used to create stack.')
                ),
                PASSWORD: properties.Schema(
                    properties.Schema.STRING,
                    _('Password to authenticate the user.')
                ),
                TENANT_NAME: properties.Schema(
                    properties.Schema.STRING,
                    _('Tenant in which stack will be created.')
                ),
                REGION_NAME: properties.Schema(
                    properties.Schema.STRING,
                    _('Region name in which stack will be created.')
                ),
            }
        ),
        TEMPLATE_URL: properties.Schema(
            properties.Schema.STRING,
            _('The URL of a template that specifies the stack to be created '
              'as a resource.'),
            required=True,
            update_allowed=True
        ),
        TIMEOUT_IN_MINS: properties.Schema(
            properties.Schema.NUMBER,
            _('The length of time, in minutes, to wait for the nested stack '
              'creation.'),
            update_allowed=True
        ),
        PARAMETERS: properties.Schema(
            properties.Schema.MAP,
            _('The set of parameters passed to this nested stack.'),
            update_allowed=True
        ),
    }

    update_allowed_keys = ('Properties',)

    def __init__(self, name, json_snippet, stack):
        super(RemoteNestedStack, self).__init__(name, json_snippet, stack)
        self.hc = None

    def _get_context(self):
        ctx_props = self.properties.get(self.CONTEXT)
        ctx = {
            'username': ctx_props['username'] or self.context.username,
            'password': ctx_props['password'] or self.context.password,
            'tenant': ctx_props['tenant_name'] or self.context.tenant,
            'auth_url': self.context.auth_url,
        }
        return RequestContext.from_dict(ctx)

    def _get_region_name(self):
        ctx_props = self.properties.get(self.CONTEXT)
        if ctx_props:
            return ctx_props['region_name']

    def heat(self):
        if self.hc:
            return self.hc

        ctx = self._get_context()
        kc = hkc.KeystoneClient(ctx)
        args = {
            'auth_url': ctx.auth_url,
            'token': kc.auth_token,
            'username': ctx.username,
            'password': ctx.password,
        }
        endpoint = kc.url_for(service_type='orchestration',
                              region_name=self._get_region_name())
        self.hc = heatclient.Client('1', endpoint, **args)
        return self.hc

    def handle_create(self):
        try:
            template_data = urlfetch.get(self.properties[self.TEMPLATE_URL])
        except (exceptions.RequestException, IOError) as r_exc:
            raise ValueError(_("Could not fetch remote template '%(url)s': "
                             "%(exc)s") %
                             {'url': self.properties[self.TEMPLATE_URL],
                              'exc': str(r_exc)})

        template = template_format.parse(template_data)

        fields = {
            'stack_name': self.physical_resource_name(),
            'template': template,
            'timeout_mins': self.properties[self.TIMEOUT_IN_MINS],
            'disable_rollback': True,
            'parameters': self.properties[self.PARAMETERS],
            'files': self.stack.t.files
        }

        remote_stack_id = self.heat().stacks.create(**fields)['stack']['id']
        self.resource_id_set(remote_stack_id)

    def handle_update(self, json_snippet, tmpl_diff, prop_diff):
        if self.resource_id is not None and prop_diff \
           and self.CONTEXT not in prop_diff:
            self.properties = Properties(self.properties_schema,
                                         json_snippet.get('Properties', {}),
                                         function.resolve,
                                         self.name)

            try:
                template_data = urlfetch.get(
                    self.properties[self.TEMPLATE_URL])
            except (exceptions.RequestException, IOError) as r_exc:
                raise ValueError(
                    _("Could not fetch remote template '%(url)s': "
                      "%(exc)s") % {'url': self.properties[self.TEMPLATE_URL],
                                    'exc': str(r_exc)})

            template = template_format.parse(template_data)

            fields = {
                'stack_name': self.physical_resource_name(),
                'template': template,
                'timeout_mins': self.properties[self.TIMEOUT_IN_MINS],
                'disable_rollback': True,
                'parameters': self.properties[self.PARAMETERS],
                'files': self.stack.t.files
            }

            self.heat().stacks.update(**fields)
        else:
            raise resource.UpdateReplace(self.name)

    def handle_delete(self):
        if self.resource_id is not None:
            try:
                self.heat().stacks.delete(stack_id=self.resource_id)
            except heat_exp.HTTPNotFound:
                logger.warn(_("Remote Stack %s already gone.") % self.name)

    def _get_status(self):
        stack = self.heat().stacks.get(stack_id=self.resource_id)
        return stack.stack_status

    def check_create_complete(self, *args):
        status = self._get_status()
        if status == 'CREATE_FAILED':
            exc = Exception(_('Remote stack creation failed.'))
            raise exception.ResourceFailure(exc, self, self.action)
        return not (status == 'CREATE_IN_PROGRESS')

    def check_update_complete(self, *args):
        status = self._get_status()
        if status == 'UPDATE_FAILED':
            exc = Exception(_('Remote stack update failed.'))
            raise exception.ResourceFailure(exc, self, self.action)
        return not (status == 'UPDATE_IN_PROGRESS')

    def check_delete_complete(self, *args):
        if self.resource_id is None:
            return True

        try:
            status = self._get_status()
        except heat_exp.HTTPNotFound:
            return

        if status == 'DELETE_FAILED':
            exc = Exception(_('Remote stack deletion failed.'))
            raise exception.ResourceFailure(exc, self, self.action)
        return not (status == 'DELETE_IN_PROGRESS')

    def FnGetAtt(self, key):
        if key and not key.startswith('Outputs.'):
            raise exception.InvalidTemplateAttribute(resource=self.name,
                                                     key=key)
        stack = self.heat().stacks.get(stack_id=self.resource_id)
        output_key = key.partition('.')[-1]
        for output in stack.outputs:
            if output['output_key'] == output_key:
                return output['output_value']
        return None


def resource_mapping():
    if heatclient is None:
        return {}
    return {
        'OS::Heat::RemoteStack': RemoteNestedStack,
    }

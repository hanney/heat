# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import copy
import mock

from heat.common import exception
from heat.common import template_format
from heat.engine import resource
from heat.engine import scheduler
from heat.engine.resources import remote_stack
from heat.tests import utils
from heat.tests.common import HeatTestCase


remote_stack_template = '''
{
  "AWSTemplateFormatVersion" : "2010-09-09",
  "Description" : "Template to test RemoteStack resource",
  "Parameters" : {},
  "Resources" : {
    "RemoteStack": {
      "Type": "OS::Heat::RemoteStack",
      "Properties": {
        "Context": {
            "username": "admin",
            "password": "openstack",
            "tenant": "demo",
            "region_name": "RegionOne"
        },
        "TemplateURL": "https://server.test/the.template",
        "TimeoutInMinutes": 60,
        "Parameters": {
          "KeyName": "foo"
        }
      }
    }
  }
}
'''

nested_template = '''
{
  "AWSTemplateFormatVersion" : "2010-09-09",
  "Description" : "Nested template to test RemoteStack resource",
  "Parameters" : {
    "KeyName": {
      "Type": String
    }
  },
  "Outputs": {
    "Foo" : {
      "Value": "bar"
    }
  }
}
'''


class RemoteStackTest(HeatTestCase):

    STACK = {
        'stack': {
            'id': 'c8a19429-7fde-47ea-a42f-40045488226c',
            'stack_name': 'teststack',
            'description': 'No description',
            'stack_status_reason': 'Stack create completed successfully',
            'creation_time': '2013-08-04T20:57:55Z',
            'updated_time': '2013-08-04T20:57:55Z',
            'stack_status': 'CREATE_COMPLETE'
        }
    }

    def setUp(self):
        super(RemoteStackTest, self).setUp()
        utils.setup_dummy_db()
        self.heat = mock.MagicMock()
        self.heatclient = mock.MagicMock()
        self.heat.return_value = self.heatclient
        self.stacks = self.heatclient.stacks
        self.stacks.create.return_value = self.STACK

    def create_remote_stack(self, heatclient=None):
        snippet = template_format.parse(remote_stack_template)
        self.stack = utils.parse_stack(snippet)
        self.ctx = self.stack.context
        rsrc = remote_stack.RemoteNestedStack(
            'remote_stack',
            snippet['Resources']['RemoteStack'],
            self.stack)
        if heatclient is not None:
            rsrc.heat = heatclient
        return rsrc

    @utils.stack_delete_after
    def test_get_context(self):
        rsrc = self.create_remote_stack()
        ctx = rsrc._get_context()
        self.assertEqual('admin', ctx.username)
        self.assertEqual('openstack', ctx.password)
        self.assertEqual('demo', ctx.tenant)
        self.assertEqual('RegionOne', ctx.region_name)

    @utils.stack_delete_after
    def test_keystone(self):
        rsrc = self.create_remote_stack()
        with mock.patch('heat.common.heat_keystoneclient.KeystoneClient') as \
                hkc_mock:
            with mock.patch('heatclient.client.Client') as hc_mock:
                hkc = hkc_mock.return_value
                hkc.url_for.return_value = 'http://example.com/1234'
                hkc.auth_token = 'token'
                rsrc.heat()
                hkc.url_for.assert_called_with(service_type='orchestration',
                                               region_name='RegionOne')
                ctx = hkc_mock.call_args_list[0][0][0]
                self.assertEqual('admin', ctx.username)
                self.assertEqual('openstack', ctx.password)
                self.assertEqual('demo', ctx.tenant)
                self.assertEqual('RegionOne', ctx.region_name)
                hc_mock.assert_called_with(
                    '1',
                    'http://example.com/1234',
                    auth_url='http://server.test:5000/v2.0',
                    token='token',
                    username='admin',
                    password='openstack')

    @utils.stack_delete_after
    @mock.patch('heat.common.urlfetch.get',
                mock.MagicMock(return_value=nested_template))
    def test_create(self):
        rsrc = self.create_remote_stack(self.heat)
        scheduler.TaskRunner(rsrc.create)()
        self.assertEqual((rsrc.CREATE, rsrc.COMPLETE), rsrc.state)
        self.assertEqual('c8a19429-7fde-47ea-a42f-40045488226c',
                         rsrc.resource_id)
        fields = {
            'stack_name': rsrc.physical_resource_name(),
            'template': template_format.parse(nested_template),
            'timeout_mins': 60,
            'disable_rollback': True,
            'parameters': {'KeyName': 'foo'},
            'files': {}
        }
        self.stacks.create.assert_called_with(**fields)

    @utils.stack_delete_after
    @mock.patch('heat.common.urlfetch.get',
                mock.MagicMock(return_value=nested_template))
    def test_delete(self):
        rsrc = self.create_remote_stack(self.heat)
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)
        self.stacks.delete.assert_called_with(stack_id=rsrc.resource_id)

    @utils.stack_delete_after
    def test_properties(self):
        rsrc = self.create_remote_stack(self.heat)
        ctx = rsrc.properties.get('Context')
        self.assertEqual('admin', ctx['username'])
        self.assertEqual('openstack', ctx['password'])
        self.assertEqual('demo', ctx['tenant'])
        self.assertEqual('RegionOne', ctx['region_name'])
        self.assertEqual('https://server.test/the.template',
                         rsrc.properties.get('TemplateURL'))
        self.assertEqual(60, rsrc.properties.get('TimeoutInMinutes'))

    @utils.stack_delete_after
    @mock.patch('heat.common.urlfetch.get',
                mock.MagicMock(return_value=nested_template))
    def test_attribute(self):
        rsrc = self.create_remote_stack(self.heat)
        scheduler.TaskRunner(rsrc.create)()
        created_stack = mock.MagicMock()
        created_stack.outputs = [
            {
                'output_key': 'Foo',
                'output_value': 'bar'
            }
        ]
        self.stacks.get.return_value = created_stack
        self.assertEqual('bar', rsrc.FnGetAtt('Outputs.Foo'))
        self.stacks.get.assert_called_with(
            stack_id='c8a19429-7fde-47ea-a42f-40045488226c')

    @utils.stack_delete_after
    @mock.patch('heat.common.urlfetch.get',
                mock.MagicMock(return_value=nested_template))
    def test_attribute_failed(self):
        rsrc = self.create_remote_stack(self.heat)
        scheduler.TaskRunner(rsrc.create)()
        error = self.assertRaises(exception.InvalidTemplateAttribute,
                                  rsrc.FnGetAtt, 'non-existent_property')
        self.assertEqual(
            'The Referenced Attribute (remote_stack non-existent_property) is '
            'incorrect.',
            str(error))

    @utils.stack_delete_after
    @mock.patch('heat.common.urlfetch.get',
                mock.MagicMock(return_value=nested_template))
    def test_update(self):
        rsrc = self.create_remote_stack(self.heat)
        scheduler.TaskRunner(rsrc.create)()
        update_template = copy.deepcopy(rsrc.t)
        update_template['Properties']['Parameters']['KeyName'] = 'bar'
        self.stacks.update.return_value = self.STACK
        scheduler.TaskRunner(rsrc.update, update_template)()
        self.assertEqual('bar', rsrc.properties.get('Parameters')['KeyName'])

    @utils.stack_delete_after
    @mock.patch('heat.common.urlfetch.get',
                mock.MagicMock(return_value=nested_template))
    def test_update_with_replace(self):
        rsrc = self.create_remote_stack(self.heat)
        scheduler.TaskRunner(rsrc.create)()
        update_template = copy.deepcopy(rsrc.t)
        update_template['Properties']['Context']['region_name'] = 'RegionTwo'
        self.assertRaises(resource.UpdateReplace,
                          scheduler.TaskRunner(rsrc.update, update_template))

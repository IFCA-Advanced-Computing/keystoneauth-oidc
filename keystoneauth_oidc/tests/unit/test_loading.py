# Copyright 2016 Spanish National Research Council
# Copyright 2016 INDIGO-DataCloud
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import uuid

import keystoneauth1.exceptions.auth_plugins
from keystoneauth1 import loading
from keystoneauth1.tests.unit.loading import test_v3
from keystoneauth1.tests.unit import utils


class OpenIDConnectAuthCodeTests(test_v3.OpenIDConnectBaseTests,
                                 utils.TestCase):

    plugin_name = "v3oidccode"

    def test_options(self):
        options = loading.get_plugin_loader(self.plugin_name).get_options()
        self.assertTrue(
            set(['authorization-endpoint', 'redirect-port']).issubset(
                set([o.name for o in options]))
        )

    def test_basic(self):
        access_token_endpoint = uuid.uuid4().hex
        authorization_endpoint = uuid.uuid4().hex
        redirect_port = 12345
        scope = uuid.uuid4().hex
        identity_provider = uuid.uuid4().hex
        protocol = uuid.uuid4().hex
        client_id = uuid.uuid4().hex
        client_secret = uuid.uuid4().hex

        oidc = self.create(identity_provider=identity_provider,
                           protocol=protocol,
                           access_token_endpoint=access_token_endpoint,
                           authorization_endpoint=authorization_endpoint,
                           redirect_port=redirect_port,
                           client_id=client_id,
                           client_secret=client_secret,
                           scope=scope)

        self.assertEqual(scope, oidc.scope)
        self.assertEqual(identity_provider, oidc.identity_provider)
        self.assertEqual(protocol, oidc.protocol)
        self.assertEqual(access_token_endpoint, oidc.access_token_endpoint)
        self.assertEqual(authorization_endpoint, oidc.authorization_endpoint)
        self.assertEqual(redirect_port, oidc.redirect_port)
        self.assertEqual(client_id, oidc.client_id)
        self.assertEqual(client_secret, oidc.client_secret)

    def test_no_endpoints(self):
        access_token_endpoint = uuid.uuid4().hex
        redirect_port = 12345
        scope = uuid.uuid4().hex
        identity_provider = uuid.uuid4().hex
        protocol = uuid.uuid4().hex
        client_id = uuid.uuid4().hex
        client_secret = uuid.uuid4().hex

        self.assertRaises(keystoneauth1.exceptions.auth_plugins.OptionError,
                          self.create,
                          identity_provider=identity_provider,
                          protocol=protocol,
                          access_token_endpoint=access_token_endpoint,
                          redirect_port=redirect_port,
                          client_id=client_id,
                          client_secret=client_secret,
                          scope=scope)

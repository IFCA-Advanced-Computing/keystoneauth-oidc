# coding=utf-8

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

import socket
import uuid

from keystoneauth1.tests.unit.identity import test_identity_v3_oidc
from keystoneauth1.tests.unit import oidc_fixtures
from keystoneauth1.tests.unit import utils
import mock
from six.moves import urllib

from keystoneauth_oidc_authz_code import exceptions
from keystoneauth_oidc_authz_code import plugin as oidc


class OIDCAuthorizationGrantTests(test_identity_v3_oidc.BaseOIDCTests,
                                  utils.TestCase):
    def setUp(self):
        super(OIDCAuthorizationGrantTests, self).setUp()

        self.GRANT_TYPE = 'authorization_code'

        self.AUTHORIZATION_ENDPOINT = 'https://localhost:8020/oidc/authn'

        self.plugin = oidc.OidcAuthorizationCode(
            self.AUTH_URL,
            self.IDENTITY_PROVIDER,
            self.PROTOCOL,
            client_id=self.CLIENT_ID,
            client_secret=self.CLIENT_SECRET,
            access_token_endpoint=self.ACCESS_TOKEN_ENDPOINT,
            authorization_endpoint=self.AUTHORIZATION_ENDPOINT,
            project_name=self.PROJECT_NAME)

    def test_no_authorization_endpoint(self):
        plugin = self.plugin.__class__(self.AUTH_URL,
                                       self.IDENTITY_PROVIDER,
                                       self.PROTOCOL,
                                       client_id=self.CLIENT_ID,
                                       client_secret=self.CLIENT_SECRET)

        self.assertRaises(exceptions.OidcAuthorizationEndpointNotFound,
                          plugin._get_authorization_endpoint,
                          self.session)

    def test_load_discovery(self):
        self.requests_mock.get(self.DISCOVERY_URL,
                               json=oidc_fixtures.DISCOVERY_DOCUMENT)

        plugin = self.plugin.__class__(self.AUTH_URL,
                                       self.IDENTITY_PROVIDER,
                                       self.PROTOCOL,
                                       client_id=self.CLIENT_ID,
                                       client_secret=self.CLIENT_SECRET,
                                       discovery_endpoint=self.DISCOVERY_URL)
        self.assertEqual(
            oidc_fixtures.DISCOVERY_DOCUMENT["token_endpoint"],
            plugin._get_access_token_endpoint(self.session)
        )
        self.assertEqual(
            oidc_fixtures.DISCOVERY_DOCUMENT["authorization_endpoint"],
            plugin._get_authorization_endpoint(self.session)
        )

    def test_initial_call_to_get_access_token(self):
        """Test initial call, expect JSON access token."""
        # Mock the output that creates the access token
        self.requests_mock.post(
            self.ACCESS_TOKEN_ENDPOINT,
            json=oidc_fixtures.ACCESS_TOKEN_VIA_AUTH_GRANT_RESP)

        # Prep all the values and send the request
        grant_type = 'authorization_code'
        payload = {'grant_type': grant_type,
                   'redirect_uri': self.REDIRECT_URL,
                   'code': self.CODE}
        self.plugin._get_access_token(self.session, payload)

        # Verify the request matches the expected structure
        last_req = self.requests_mock.last_request
        self.assertEqual(self.ACCESS_TOKEN_ENDPOINT, last_req.url)
        self.assertEqual('POST', last_req.method)
        encoded_payload = urllib.parse.urlencode(payload)
        self.assertEqual(encoded_payload, last_req.body)

    @mock.patch.object(oidc.OidcAuthorizationCode, "_get_authorization_code")
    def test_get_payload(self, mock_get_auth_code):
        code = uuid.uuid4().hex
        mock_get_auth_code.return_value = code
        payload = {'redirect_uri': self.plugin.redirect_uri, 'code': code,
                   'scope': self.plugin.scope}
        self.assertDictEqual(payload,
                             self.plugin.get_payload(self.session))

    @mock.patch("webbrowser.open")
    @mock.patch.object(oidc.OidcAuthorizationCode, "_wait_for_code")
    def test__get_authorization_code(self,
                                     mock_wait_for_code,
                                     mock_webbrowser):
        code = uuid.uuid4().hex
        mock_wait_for_code.return_value = code
        payload = {"client_id": self.CLIENT_ID,
                   "response_type": "code",
                   "scope": self.plugin.scope,
                   "redirect_uri": self.plugin.redirect_uri}

        url = "%s?%s" % (self.AUTHORIZATION_ENDPOINT,
                         urllib.parse.urlencode(payload))
        self.assertEqual(code,
                         self.plugin._get_authorization_code(self.session))
        mock_webbrowser.assert_called_with(url, new=1, autoraise=True)

    @mock.patch("keystoneauth_oidc_authz_code.plugin._ClientCallbackServer")
    def test_wait_for_code_socket_error(self, mock_callback):
        mock_callback.side_effect = socket.error
        self.assertRaises(socket.error,
                          self.plugin._wait_for_code)
        address = (self.plugin.redirect_host, self.plugin.redirect_port)
        mock_callback.assert_called_with(address, oidc._ClientCallbackHandler)

    @mock.patch("keystoneauth_oidc_authz_code.plugin._ClientCallbackServer")
    def test_wait_for_code_error(self, mock_callback):
        m = mock.MagicMock()
        mock_callback.return_value = m
        m.handle_request.return_value = None
        m.code = None

        self.assertRaises(exceptions.MissingOidcAuthorizationCode,
                          self.plugin._wait_for_code)

        address = (self.plugin.redirect_host, self.plugin.redirect_port)
        mock_callback.assert_called_with(address, oidc._ClientCallbackHandler)
        m.handle_request.assert_called()

    @mock.patch("keystoneauth_oidc_authz_code.plugin._ClientCallbackServer")
    def test_wait_for_code(self, mock_callback):
        m = mock.MagicMock()
        mock_callback.return_value = m
        m.handle_request.return_value = None
        code = uuid.uuid4().hex
        m.code = code

        self.assertEqual(code,
                         self.plugin._wait_for_code())

        address = (self.plugin.redirect_host, self.plugin.redirect_port)
        mock_callback.assert_called_with(address, oidc._ClientCallbackHandler)
        m.handle_request.assert_called()

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

from keystoneauth1 import exceptions
from keystoneauth1 import loading
from keystoneauth1.loading._plugins.identity import v3

from keystoneauth_oidc_authz_code import plugin


class OpenIDConnectAuthorizationCode(v3._OpenIDConnectBase):

    @property
    def plugin_class(self):
        return plugin.OidcAuthorizationCode

    def get_options(self):
        options = super(OpenIDConnectAuthorizationCode, self).get_options()

        options.extend([
            loading.Opt('authorization-endpoint',
                        help='OpenID Connect Provider Authorization Endpoint.'
                             'Note that if a discovery document is passed '
                             'this option will override the endpoint provided '
                             'by the server in the discovery document.'),
            loading.Opt('redirect-port',
                        default=8080,
                        type=int,
                        help='Port where the callback server will be '
                        'listening. By default this server will listen on '
                        'localhost and port 8080 (therefore the redirect URL '
                        'to be configured in the authentication server would '
                        'is http://localhost:8080), but you can adjust the '
                        'port here in case you cannot bind on that port.'),
        ])

        return options

    def load_from_options(self, **kwargs):
        if not (kwargs.get('authorization_endpoint') or
                kwargs.get('discovery_endpoint')):
            m = ("You have to specify either an 'authorization-endpoint' or "
                 "a 'discovery-endpoint'.")
            raise exceptions.OptionError(m)

        return super(OpenIDConnectAuthorizationCode,
                     self).load_from_options(**kwargs)

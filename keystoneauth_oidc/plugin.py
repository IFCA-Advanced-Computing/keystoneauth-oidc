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
import webbrowser

from keystoneauth1 import _utils as utils
from keystoneauth1 import access
from keystoneauth1.identity.v3 import federation
from keystoneauth1.identity.v3 import oidc
from positional import positional
from six.moves import BaseHTTPServer
from six.moves import urllib
from six.moves.urllib import parse as urlparse

from keystoneauth_oidc import exceptions

_logger = utils.get_logger(__name__)


class _ClientCallbackServer(BaseHTTPServer.HTTPServer):
    """HTTP server to handle the OpenID Connect callback to localhost.

    This server will wait for a single request, storing the authorization code
    obtained from the incoming request into the 'code' attribute.
    """

    code = None

    def server_bind(self):
        """Override original bind and set a timeout.

        Authentication may fail and we could get stuck here forever, so this
        method sets up a sane timeout.
        """
        # NOTE(aloga): cannot call super here, as HTTPServer does not have
        # object as an ancestor
        BaseHTTPServer.HTTPServer.server_bind(self)
        self.socket.settimeout(60)


class _ClientCallbackHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """HTTP request handler for the OpenID Connect redirect callback.

    The OpenID Connect authorization code grant type is a redirection based
    flow where the client needs to be capable of receiving incoming requests
    (via redirection), where the access code will be obtained.

    This class implements a request handler that will process a single request
    and store the obtained code into the server's 'code' attribute
    """

    def do_GET(self):
        """Handle a GET request and obtain an authorization code.

        This method will process the query parameters and get an
        authorization code from them, if any, storing it in the
        server's `code` attribute.
        """
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(
            b"<html><head><title>Authentication Status OK</title></head>"
            b"<body><p>The authentication flow has been completed.</p>"
            b"<p>You can close this window.</p>"
            b"</body></html>")
        parsed = urlparse.urlparse(self.path)
        query = urlparse.parse_qs(parsed.query)
        code = query.get("code", [None])[0]
        state = query.get("state", [None])[0]
        self.server.code = code
        self.server.state = state

    def log_message(self, format, *args):
        """Do not log messages to stdout."""


def _wait_for_code(redirect_host, redirect_port):
    """Spawn an HTTP server and wait for the auth code.

    :param redirect_host: The hostname where the authorization request will
                            be redirected. This normally is localhost. This
                            indicates the hostname where the callback http
                            server will listen.
    :type redirect_host: string

    :param redirect_port: The port where the authorization request will
                            be redirected. This indicates the port where the
                            callback http server will bind to.
    :type redirect_port: int
    """
    server_address = (redirect_host, redirect_port)
    try:
        httpd = _ClientCallbackServer(server_address,
                                      _ClientCallbackHandler)
    except socket.error:
        _logger.error("Cannot spawn the callback server on port "
                      "%s, please specify a different port." %
                      redirect_port)
        raise
    httpd.handle_request()
    if httpd.code is not None:
        return httpd.code, httpd.state
    else:
        raise exceptions.MissingOidcAuthorizationCode()


class OidcAuthorizationCode(oidc._OidcBase):
    """Implementation for OpenID Connect Authorization Code."""

    grant_type = 'authorization_code'

    @positional(4)
    def __init__(self, auth_url, identity_provider, protocol,
                 client_id, client_secret,
                 access_token_endpoint=None,
                 authorization_endpoint=None,
                 discovery_endpoint=None,
                 access_token_type='access_token',
                 redirect_host="localhost", redirect_port=8080,
                 **kwargs):
        """The OpenID Authorization Code plugin expects the following.

        :param redirect_host: The hostname where the authorization request will
                              be redirected. This normally is localhost. This
                              indicates the hostname where the callback http
                              server will listen.
        :type redirect_host: string

        :param redirect_port: The port where the authorization request will
                              be redirected. This indicates the port where the
                              callback http server will bind to.
        :type redirect_port: int
        """
        super(OidcAuthorizationCode, self).__init__(
            auth_url=auth_url,
            identity_provider=identity_provider,
            protocol=protocol,
            client_id=client_id,
            client_secret=client_secret,
            access_token_endpoint=access_token_endpoint,
            discovery_endpoint=discovery_endpoint,
            access_token_type=access_token_type,
            **kwargs)
        self.authorization_endpoint = authorization_endpoint
        self.redirect_host = redirect_host
        self.redirect_port = int(redirect_port)
        self.redirect_uri = "http://%s:%s" % (self.redirect_host,
                                              self.redirect_port)

    def _get_authorization_endpoint(self, session):
        """Get the "authorization_endpoint" for the OpenID Connect flow.

        This method will return the correct authorization endpoint to be used.
        If the user has explicitly passed an authoriation_token_endpoint to the
        constructor that will be returned. If there is no explicit endpoint and
        a discovery url is provided, it will try to get it from the discovery
        document. If nothing is found, an exception will be raised.

        :param session: a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :return: the endpoint to use
        :rtype: string or None if no endpoint is found
        """
        if self.authorization_endpoint is not None:
            return self.authorization_endpoint

        discovery = self._get_discovery_document(session)
        endpoint = discovery.get("authorization_endpoint")
        if endpoint is None:
            raise exceptions.OidcAuthorizationEndpointNotFound()
        return endpoint

    def _get_authorization_code(self, session):
        """Get an authorization code from the authorization endpoint.

        :param session: a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        """
        payload = {"client_id": self.client_id,
                   "response_type": "code",
                   "scope": self.scope,
                   "redirect_uri": self.redirect_uri}

        url = "%s?%s" % (self._get_authorization_endpoint(session),
                         urllib.parse.urlencode(payload))

        webbrowser.open(url, new=1, autoraise=True)
        code, _ = _wait_for_code(self.redirect_host, self.redirect_port)
        return code

    def get_payload(self, session):
        """Get an authorization grant for the "authorization_code" grant type.

        :param session: a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :returns: a python dictionary containing the payload to be exchanged
        :rtype: dict
        """
        code = self._get_authorization_code(session)

        payload = {'redirect_uri': self.redirect_uri, 'code': code,
                   'scope': self.scope}

        return payload


class OpenIDConnect(federation.FederationBaseAuth):
    """Implementation for OpenID Connect authentication."""
    @positional(3)
    def __init__(self, auth_url, identity_provider, protocol,
                 redirect_host="localhost", redirect_port=8080,
                 **kwargs):
        """The OpenID Connect plugin expects the following arguments.

        :param redirect_host: The hostname where the authorization request will
                              be redirected. This normally is localhost. This
                              indicates the hostname where the callback http
                              server will listen.
        :type redirect_host: string

        :param redirect_port: The port where the authorization request will
                              be redirected. This indicates the port where the
                              callback http server will bind to.
        :type redirect_port: int
        """
        super(OpenIDConnect, self).__init__(
            auth_url=auth_url,
            identity_provider=identity_provider,
            protocol=protocol,
            **kwargs)
        self.redirect_host = redirect_host
        self.redirect_port = int(redirect_port)
        self.redirect_uri = "http://%s:%s" % (self.redirect_host,
                                              self.redirect_port)

    def _get_keystone_token(self, session):

        # We initiate the auth request to Keystone. We indicate the oscli=1
        # query param so as to start and out-of-bound authentication.
        auth_response = session.post(self.federated_token_url + "?oscli=1",
                                     redirect=False,
                                     authenticated=False)

        # Keystone will return a 302 redirect. We need to point the user to
        # that URL so that the auth request is authorized.
        redirect_url = auth_response.headers["location"]

        webbrowser.open(redirect_url, new=1, autoraise=True)
        code, state = _wait_for_code(self.redirect_host, self.redirect_port)

        # Now that we have the code and state, we can finish the token request
        # by sending them back to the Keystone auth endpoing, finishing the
        # out-of-bound authentication
        params = {
            "code": code,
            "state": state,
            "oscli": 1,
        }
        auth_response = session.get(self.federated_token_url,
                                    params=params,
                                    authenticated=False)

        return auth_response

    def get_unscoped_auth_ref(self, session):
        """Authenticate with a Keystone server with OpenID Connect.

        This plugin expects that the OpenID Connect Client is the Keystone
        server, not the OpenStack or Keystone client. No OpenID credentials
        need to be configured.

        This plugin initiates an auth request to Keystone (to the federation
        endpoint) with an special query parameter (oscli=1), indicating that
        the OpenID Connect redirection should not be made to the Keystone
        server configured URL, but to http://localhost:8080. This way we can
        perform out-of-bound authentication as follows: When the Keystone
        server returns the redirection, we intercept it and, instead of
        following it, we open a web browser, so that the user can authorize the
        request, spawning a web server on locahost:8080. After the user has
        authorized the auth request, the web browser is redirected to
        http://localhost:8080 where we can get the auth code, and send it back
        to Keystone to complete the authentication.

        :param session: a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :returns: a token data representation
        :rtype: :py:class:`keystoneauth1.access.AccessInfoV3`
        """

        response = self._get_keystone_token(session)

        return access.create(resp=response)

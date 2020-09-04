# OpenID Connect support for OpenStack clients

[![GitHub issues](https://img.shields.io/github/issues/IFCA/keystoneauth-oidc.svg)](https://github.com/IFCA/keystoneauth-oidc/issues)
[![Travis status](https://img.shields.io/travis/IFCA/keystoneauth-oidc.svg)](https://travis-ci.org/IFCA/keystoneauth-oidc)
[![PyPI version](https://img.shields.io/pypi/v/keystoneauth-oidc.svg)](https://pypi.python.org/pypi/keystoneauth-oidc/)
[![PyPI downloads](https://img.shields.io/pypi/dm/keystoneauth-oidc.svg)](https://pypi.python.org/pypi/keystoneauth-oidc/)
[![GitHub license](https://img.shields.io/badge/license-Apache%202-blue.svg)](https://raw.githubusercontent.com/IFCA/keystoneauth-oidc/master/LICENSE)

This is a set of authentication plugins for the OpenStack clients (namely for
the [keystoneauth1](https://github.com/openstack/keystoneauth) library) which
provides client support for authentication against an OpenStack Keystone server
configured to support OpenID Connect using the [Keystone Open ID Connect
plugin](https://github.com/IFCA/keystone-oidc-auth-plugin) or the Apache's
[mod_auth_openidc](https://github.com/zmartzone/mod_auth_openidc), as described
below.

## Available plugins

### `v3oidc` plugin

This plugin allows you to authenticate with a Keystone server configured to use
the [Keystone Open ID Connect plugin](https://github.com/IFCA/keystone-oidc-auth-plugin).
It will perform out-of-bound authentication with the sever, meaning that the
only OpenID Connect client (Relying Party) is the Keystone Server.

No OpenID Connect credentials are required in this case.

### `v3oidccode` plugin (old method)

This plugin allows to authenticate against Keystone using the Authorization
Code grant type of OpenID Connect and OAuth 2.0, using the OpenStack client as
an OpenID Connect Relying Party. This plugin is compatible with Keystone
configured with the Apache HTTP server and the
[mod_auth_openidc](https://github.com/zmartzone/mod_auth_openidc) and the
[Keystone Open ID Connect plugin](https://github.com/IFCA/keystone-oidc-auth-plugin).

This plugin requires that you configure an OpenID Connect client in your OpenID
Connect Provider and pass the client credentials to the plugin. The OpenStack
CLI will handle the authentication with the OpenID Connect Provider, obtaining
and access token, that will be exchanged with the Keystone server in order to
obtain a Keystone token.


## Installation

Install it via pip:

    pip install keystoneauth-oidc

Or clone the repo and install it:

    git clone https://github.com/IFCA/keystoneauth-oidc
    cd keystoneauth-oidc
    pip install .

## Usage

### `v3oidc` plugin

You have to specify the `v3oidc` in the `--os-auth-type`. The
`<identity-provider>` and `<protocol>` must be provided by the OpenStack cloud
provider.

- Unscoped token:

        openstack --os-auth-url https://keystone.example.org:5000/v3 \
            --os-auth-type v3oidccode \
            --os-identity-provider <identity-provider> \
            --os-protocol <protocol> \
            --os-identity-api-version 3 \
            --os-discovery-endpoint https://idp.example.org/.well-known/openid-configuration \
            --os-openid-scope "openid profile email" \
            token issue

- Scoped token:

        openstack --os-auth-url https://keystone.example.org:5000/v3 \
            --os-auth-type v3oidc \
            --os-identity-provider <identity-provider> \
            --os-protocol <protocol> \
            --os-project-name <project> \
            --os-project-domain-id <project-domain> \
            --os-identity-api-version 3 \
            --os-openid-scope "openid profile email" \
            token issue


### `v3oidccode` plugin (old method)

First of all, you need to create an OpenID Connect client in your OpenID Connect Provider.
Then, you have to specify the `v3oidccode` in the `--os-auth-type` option and provide a
valid autorization endpoint with `--os-authorization-endpoint` or a valid discovery
endpoint with `--os-discovery-endpoint`. The `<identity-provider>` and
`<protocol>` must be provided by the OpenStack cloud provider.

- Unscoped token:

        openstack --os-auth-url https://keystone.example.org:5000/v3 \
            --os-auth-type v3oidccode \
            --os-identity-provider <identity-provider> \
            --os-protocol <protocol> \
            --os-identity-api-version 3 \
            --os-client-id <OpenID Connect client ID> \
            --os-client-secret <OpenID Connect client secret> \
            --os-discovery-endpoint https://idp.example.org/.well-known/openid-configuration \
            --os-openid-scope "openid profile email" \
            token issue

- Scoped token:

        openstack --os-auth-url https://keystone.example.org:5000/v3 \
            --os-auth-type v3oidccode \
            --os-identity-provider <identity-provider> \
            --os-protocol <protocol> \
            --os-project-name <project> \
            --os-project-domain-id <project-domain> \
            --os-identity-api-version 3 \
            --os-client-id <OpenID Connect client ID> \
            --os-client-secret <OpenID Connect client secret> \
            --os-discovery-endpoint https://idp.example.org/.well-known/openid-configuration \
            --os-openid-scope "openid profile email" \
            token issue

### API

To be documented.

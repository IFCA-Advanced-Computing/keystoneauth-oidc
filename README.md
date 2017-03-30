# OpenID Connect Authorization Code grant type support for OpenStack clients

[![GitHub issues](https://img.shields.io/github/issues/indigo-dc/keystoneauth-oidc-authz-code.svg)](https://github.com/indigo-dc/keystoneauth-oidc-authz-code/issues)
[![Travis status](https://img.shields.io/travis/indigo-dc/keystoneauth-oidc-authz-code.svg)](https://travis-ci.org/indigo-dc/keystoneauth-oidc-authz-code)
[![PyPI version](https://img.shields.io/pypi/v/keystoneauth-oidc-authz-code.svg)](https://pypi.python.org/pypi/keystoneauth-oidc-authz-code/)
[![PyPI downloads](https://img.shields.io/pypi/dm/keystoneauth-oidc-authz-code.svg)](https://pypi.python.org/pypi/keystoneauth-oidc-authz-code/)
[![GitHub license](https://img.shields.io/badge/license-Apache%202-blue.svg)](https://raw.githubusercontent.com/indigo-dc/keystoneauth-oidc-authz-code/master/LICENSE)

This is an authentication plugin for the OpenStack Clients (namely for the
[keystoneauth1](https://github.com/openstack/keystoneauth) library) which
provides client support for using the Authorization Code grant type of OpenID
Connect.

## Installation

Install it via pip:

    pip install keystoneauth-oidc-authz-code

Or clone the repo and install it:

    git clone https://github.com/indigo-dc/keystoneauth-oidc-authz-code
    cd keystoneauth-oidc-authz-code
    pip install .

## Usage

### CLI

You have to specify the `v3oidccode` in the `--os-auth-type` option and provide a
valid autorization endpoint with `--os-authorization-endpoint` or a valid discovery
endpoint with `--os-discovery-endpoint`:

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

To be documented


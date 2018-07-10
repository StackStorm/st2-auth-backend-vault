# Licensed to the StackStorm, Inc ("StackStorm") under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import hvac

from six.moves.urllib.parse import urlparse

__all__ = [
    "VaultAuthenticationBackend"
]

LOG = logging.getLogger(__name__)

VAULT_AUTH_METHODS = [
    "app_id",
    "app_role",
    "aws",
    "azure",
    "gcp",
    "github",
    "kubernetes",
    "ldap",
    "okta",
    "radius",
    "token",
    "userpass",
]


class VaultAuthenticationBackend(object):
    """
    Backend which reads authentication information from HashiCorp Vault
    """

    def __init__(self, vault_url,
                 auth_method,
                 path=None,
                 ssl_verify=True,
                 ssl_ca_cert=None,
                 ssl_client_cert=None,
                 ssl_client_key=None):
        """
        :param keystone_url: Url of the Vault server to authenticate against.
        :type keystone_url: ``str``
        """
        # scheme://netloc/path;parameters?query#fragment
        url = urlparse(vault_url)
        if url.path != "" or url.params != "" or url.query != "" or url.fragment != "":
            raise Exception("The Vault url \"{}\" does not seem to be correct.\n"
                            "Please only set the scheme+url+port "
                            "(e.x.: http://example.com:8200)".format(vault_url))

        if auth_method not in VAULT_AUTH_METHODS:
            raise Exception("The Vault auth_method \"{}\" is not valid.\n"
                            "Please use one of the following methods: {}"
                            .format(auth_method, VAULT_AUTH_METHODS))

        if not ssl_client_cert and ssl_client_key:
            raise Exception("Invalid configuration. Variable \"ssl_client_key\" was"
                            " specified, but \"ssl_client_cert\" was left blank."
                            " When specifying \"ssl_client_key\" you must also specify"
                            " \"ssl_client_cert\"")

        self._vault_url = vault_url
        self._auth_method = auth_method
        self._path = path
        self._ssl_verify = ssl_verify
        self._ssl_ca_cert = ssl_ca_cert
        self._ssl_client_cert = ssl_client_cert
        self._ssl_client_key = ssl_client_key

        LOG.debug("Using Vault URL: {}".format(self._vault_url))
        LOG.debug("Using Vault auth method: {}".format(self._auth_method))
        if self._path:
            LOG.debug("Using Vault path: {}".format(self._path))
        else:
            LOG.debug("Using Vault default path")

        self._client_kwargs = self._make_client_kwargs(vault_url=self._vault_url,
                                                       ssl_verify=self._ssl_verify,
                                                       ssl_ca_cert=self._ssl_ca_cert,
                                                       ssl_client_cert=self._ssl_client_cert,
                                                       ssl_client_key=self._ssl_client_key)

    def _make_client_kwargs(self, vault_url,
                            ssl_verify,
                            ssl_ca_cert,
                            ssl_client_cert,
                            ssl_client_key):
        client_kwargs = {"url": vault_url}

        # set "verify" to the CA cert, if specified
        # otherwise use the boolean ssl_verify
        if ssl_ca_cert:
            LOG.debug("SSL verification automatically enabled because \"ssl_ca_cert\""
                      " was specified")
            # enable verification and use the CA cert specified
            client_kwargs["verify"] = ssl_ca_cert
        else:
            # true = verify
            # false = don"t verify
            client_kwargs["verify"] = ssl_verify
        LOG.debug("Using SSL verification: {}".format(client_kwargs["verify"]))

        # pass in a client-side SSL cert for TLS verification
        if ssl_client_cert:
            if ssl_client_key:
                # user passed in the client cert and key in different files
                client_kwargs["cert"] = (ssl_client_cert, ssl_client_key)
            else:
                # assume the user passed in a `.pem` file with both the cert and key
                # bundled into one file
                client_kwargs["cert"] = ssl_client_cert
            LOG.debug("Using SSL client cert: {}".format(client_kwargs["cert"]))
        else:
            LOG.debug("Using SSL client cert: False")

        return client_kwargs

    def authenticate(self, username, password):
        try:
            # create a Vault client
            client = hvac.Client(**self._client_kwargs)

            # execute auth, exception should be thrown if invalid
            auth_func = getattr(self, "_auth_" + self._auth_method)
            auth_func(client, username, password)

            # double check that client is authenticated before allowing them in,
            # just in case an exception was not thrown
            if not client.is_authenticated():
                raise Exception("Invalid Vault authentication")

            LOG.debug("Authentication for user \"{}\" with method \"{}\" successful"
                      .format(username, self._auth_method))
            return True
        except Exception as e:
            LOG.exception("Authentication for user \"{}\" with method \"{}\" failed: {}"
                          .format(username, self._auth_method, str(e)))

        # default to returning false, so we don"t accept auth in the face of an error
        return False

    def get_user(self, username):
        pass

    def _path_kwargs(self):
        """If this instance is configured with a custom path for auth, then use
        it istead of the default path for a given auth method.
        """
        kwargs_dict = {}
        if self._path:
            kwargs_dict["mount_point"] = self._path
        return kwargs_dict

    def _custom_auth_role_jwt(self, client, username, password, default_path):
        "Auth with role=username and jwt=password"
        mount_point = self._path if self._path else default_path
        params = {
            "role": username,
            "jwt": password,
        }
        # POST /v1/auth/<path>/login
        client.auth("/v1/auth/{0}/login".format(mount_point), json=params)

    def _custom_auth_user_pass(self, client, username, password, default_path):
        "Auth with username in URL and password in params"
        mount_point = self._path if self._path else default_path
        params = {
            "password": password,
        }
        # POST /v1/auth/<path>/login/<username>
        client.auth("/v1/auth/{0}/login/{1}".format(mount_point, username), json=params)

    def _auth_app_id(self, client, username, password):
        # https://www.vaultproject.io/docs/auth/app-id.html
        client.auth_app_id(username,  # app id
                           password,  # user id
                           **self._path_kwargs())

    def _auth_app_role(self, client, username, password):
        # https://www.vaultproject.io/docs/auth/approle.html
        client.auth_approle(username,  # role id
                            password,  # secret id
                            **self._path_kwargs())

    def _auth_aws(self, client, username, password):
        # https://www.vaultproject.io/docs/auth/aws.html
        client.auth_aws_iam(username,  # AWS_ACCESS_KEY
                            password,  # AWS_SECRET_ACCESS_KEY
                            **self._path_kwargs())

    def _auth_azure(self, client, username, password):
        # https://www.vaultproject.io/docs/auth/azure.html
        self._custom_auth_role_jwt(client, username, password, "azure")

    def _auth_gcp(self, client, username, password):
        # https://www.vaultproject.io/docs/auth/gcp.html
        self._custom_auth_role_jwt(client, username, password, "gcp")

    def _auth_github(self, client, username, password):
        # https://www.vaultproject.io/docs/auth/github.html
        client.auth_github(password,  # GitHub token
                           **self._path_kwargs())

    def _auth_kubernetes(self, client, username, password):
        # https://www.vaultproject.io/docs/auth/kubernetes.html
        self._custom_auth_role_jwt(client, username, password, "kubernetes")

    def _auth_ldap(self, client, username, password):
        # https://www.vaultproject.io/docs/auth/ldap.html
        client.auth_ldap(username, password,
                         **self._path_kwargs())

    def _auth_okta(self, client, username, password):
        # https://www.vaultproject.io/docs/auth/okta.html
        self._custom_auth_user_pass(client, username, password, "okta")

    def _auth_radius(self, client, username, password):
        # https://www.vaultproject.io/docs/auth/radius.html
        self._custom_auth_user_pass(client, username, password, "radius")

    def _auth_token(self, client, username, password):
        client.token = password
        client.lookup_token()  # throws if invalid

    def _auth_userpass(self, client, username, password):
        # https://www.vaultproject.io/docs/auth/userpass.html
        client.auth_userpass(username, password,
                             **self._path_kwargs())

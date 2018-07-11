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

import sys
import httplib

import unittest
import mock
from requests.models import Response
from six.moves.urllib.parse import urlparse

from st2auth_vault_backend.vault import VaultAuthenticationBackend

def _mock_vault_session(*args, **kwargs):
    mock_session = mock.MagicMock()
    mock_session.request.side_effect = _mock_vault_request
    return mock_session

def _mock_vault_request(*args, **kwargs):
    # try to extract username from URL path
    url = urlparse(args[1])
    path_parts = url.path.split("/")
    if url.path == "/v1/auth/token/lookup":
        return _mock_vault_token_lookup(*args, **kwargs)
    if url.path == "/v1/auth/token/lookup-self":
        return _mock_vault_token_lookup_self(*args, **kwargs)
    elif "login" in path_parts:
        return _mock_vault_login(*args, **kwargs)
    else:
        raise Exception("Unhandled url path: {}".format(url.path))

def _mock_vault_login(*args, **kwargs):
    return_codes = {
        "good": httplib.OK,
        "bad": httplib.BAD_REQUEST,
    }
    return_json = {
        "good": '{"auth": {"client_token": "good_token"}}',
        "bad": '{"errors":["invalid username or password"]}',
    }
    json = kwargs.get("json")

    # try to extract username from URL path
    url = urlparse(args[1])
    path_parts = url.path.split("/")

    # if the last part of the path is "login",
    # then username is part of the body (json)
    # else it's the last part of the path
    username = None
    if path_parts[-1] == "login":
        # app_role
        if json.get("role_id"):
            username = json.get("role_id")

        # app_id
        elif json.get("app_id"):
            username = json.get("app_id")

        # azue, gcp, (anything that uses role/jwt body)
        elif json.get("role"):
            username = json.get("role")

        # github
        elif json.get("token"):
            username = json.get("token")
    else:
        username = path_parts[-1]

    if not username:
        raise Exception("Unable to find username for URL {} with body: {}"
                        .format(args[1], json))

    res = Response()
    res.status_code = return_codes[username]
    # put json data in `._content` so that when the `.json()` function is called
    # it is parsed and returned as a dict
    res._content = return_json[username]
    return res

def _mock_vault_token_lookup_self(*args, **kwargs):
    return_codes = {
        "good_token": httplib.OK,
    }
    return_json = {
        "good_token": '{"auth": {"client_token": "good_token"}}',
    }

    headers = kwargs.get('headers')
    code = httplib.BAD_REQUEST
    return_content = '{}'
    if return_codes.get(headers['X-Vault-Token']):
        code = return_codes[headers['X-Vault-Token']]
        return_content = return_json[headers['X-Vault-Token']]

    res = Response()
    res.status_code = code
    # put json data in `._content` so that when the `.json()` function is called
    # it is parsed and returned as a dict
    res._content = return_content
    return res

def _mock_vault_token_lookup(*args, **kwargs):
    return_codes = {
        "good_token": httplib.OK,
    }
    return_json = {
        "good_token": '{"auth": {"client_token": "good_token"}}',
    }
    body = kwargs.get("json")

    headers = kwargs.get('headers')
    code = httplib.BAD_REQUEST
    return_content = '{}'
    if return_codes.get(body['token']):
        code = return_codes[body['token']]
        return_content = return_json[body['token']]

    res = Response()
    res.status_code = code
    # put json data in `._content` so that when the `.json()` function is called
    # it is parsed and returned as a dict
    res._content = return_content
    return res


class VaultAuthenticationBackendTestCase(unittest.TestCase):


    def test_init_default(self):
        backend = VaultAuthenticationBackend(vault_url="https://fake.com:8200",
                                             auth_method="app_role")

        self.assertEqual(backend._vault_url, "https://fake.com:8200")
        self.assertEqual(backend._auth_method, "app_role")
        self.assertEqual(backend._path, None)
        self.assertEqual(backend._ssl_verify, True)
        self.assertEqual(backend._ssl_ca_cert, None)
        self.assertEqual(backend._ssl_client_cert, None)
        self.assertEqual(backend._ssl_client_key, None)
        self.assertEqual(backend._client_kwargs, {"url": "https://fake.com:8200",
                                                  "verify": True})

    def test_init_auth_methods(self):
        auth_methods = [
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
        for a in auth_methods:
            backend = VaultAuthenticationBackend(vault_url="https://fake.com:8200",
                                                 auth_method=a)
            self.assertEquals(backend._auth_method, a)

    def test_init_ssl_verify_false(self):
        backend = VaultAuthenticationBackend(vault_url="https://fake.com:8200",
                                             auth_method="app_role",
                                             ssl_verify=False)

        self.assertEqual(backend._vault_url, "https://fake.com:8200")
        self.assertEqual(backend._auth_method, "app_role")
        self.assertEqual(backend._path, None)
        self.assertEqual(backend._ssl_verify, False)
        self.assertEqual(backend._ssl_ca_cert, None)
        self.assertEqual(backend._ssl_client_cert, None)
        self.assertEqual(backend._ssl_client_key, None)
        self.assertEqual(backend._client_kwargs, {"url": "https://fake.com:8200",
                                                  "verify": False})
    def test_init_ssl_ca_cert_path(self):
        backend = VaultAuthenticationBackend(vault_url="https://fake.com:8200",
                                             auth_method="app_role",
                                             ssl_ca_cert="/path/to/ssl/ca.cert")

        self.assertEqual(backend._vault_url, "https://fake.com:8200")
        self.assertEqual(backend._auth_method, "app_role")
        self.assertEqual(backend._path, None)
        self.assertEqual(backend._ssl_verify, True)
        self.assertEqual(backend._ssl_ca_cert, "/path/to/ssl/ca.cert")
        self.assertEqual(backend._ssl_client_cert, None)
        self.assertEqual(backend._ssl_client_key, None)
        self.assertEqual(backend._client_kwargs, {"url": "https://fake.com:8200",
                                                  "verify": "/path/to/ssl/ca.cert"})

    def test_init_ssl_client_cert_path(self):
        backend = VaultAuthenticationBackend(vault_url="https://fake.com:8200",
                                             auth_method="app_role",
                                             ssl_client_cert="/path/to/ssl/client.pem")

        self.assertEqual(backend._vault_url, "https://fake.com:8200")
        self.assertEqual(backend._auth_method, "app_role")
        self.assertEqual(backend._path, None)
        self.assertEqual(backend._ssl_verify, True)
        self.assertEqual(backend._ssl_ca_cert, None)
        self.assertEqual(backend._ssl_client_cert, "/path/to/ssl/client.pem")
        self.assertEqual(backend._ssl_client_key, None)
        self.assertEqual(backend._client_kwargs, {"url": "https://fake.com:8200",
                                                  "verify": True,
                                                  "cert": "/path/to/ssl/client.pem"})

    def test_init_ssl_client_cert_and_ssl_client_key(self):
        backend = VaultAuthenticationBackend(vault_url="https://fake.com:8200",
                                             auth_method="app_role",
                                             ssl_client_cert="/path/to/ssl/client.cert",
                                             ssl_client_key="/path/to/ssl/client.key")

        self.assertEqual(backend._vault_url, "https://fake.com:8200")
        self.assertEqual(backend._auth_method, "app_role")
        self.assertEqual(backend._path, None)
        self.assertEqual(backend._ssl_verify, True)
        self.assertEqual(backend._ssl_ca_cert, None)
        self.assertEqual(backend._ssl_client_cert, "/path/to/ssl/client.cert")
        self.assertEqual(backend._ssl_client_key, "/path/to/ssl/client.key")
        self.assertEqual(backend._client_kwargs, {"url": "https://fake.com:8200",
                                                  "verify": True,
                                                  "cert": ("/path/to/ssl/client.cert",
                                                           "/path/to/ssl/client.key")})

    def test_init_non_url_raises_exception(self):
        with self.assertRaises(Exception):
            VaultAuthenticationBackend(vault_url="abc",
                                       auth_method="app_role")

    def test_init_url_with_path_raises_exception(self):
        with self.assertRaises(Exception):
            VaultAuthenticationBackend(vault_url="https://fake.com:8200/path",
                                       auth_method="app_role")

    def test_init_url_with_query_raises_exception(self):
        with self.assertRaises(Exception):
            VaultAuthenticationBackend(vault_url="https://fake.com:8200/?query=def",
                                       auth_method="app_role")

    def test_init_url_with_fragment_raises_exception(self):
        with self.assertRaises(Exception):
            VaultAuthenticationBackend(vault_url="https://fake.com:8200/#fragment",
                                       auth_method="app_role")

    def test_init_url_with_params_raises_exception(self):
        with self.assertRaises(Exception):
            VaultAuthenticationBackend(vault_url="https://fake.com:8200/path;params",
                                       auth_method="app_role")

    def test_init_bad_auth_method_raises_exception(self):
        with self.assertRaises(Exception):
            VaultAuthenticationBackend(vault_url="https://fake.com:8200",
                                       auth_method="bad_auth_method")

    def test_init_ssl_key_without_ssl_cert_raises_exception(self):
        with self.assertRaises(Exception):
            VaultAuthenticationBackend(vault_url="https://fake.com:8200",
                                       auth_method="app_role",
                                       ssl_client_key="/path/to/ssl/client.key")

    def test_make_client_kwargs(self):
        backend = VaultAuthenticationBackend(vault_url="https://fake.com:8200",
                                             auth_method="app_role")
        result = backend._make_client_kwargs(vault_url="https://fake.com:8200",
                                             ssl_verify=True,
                                             ssl_ca_cert=None,
                                             ssl_client_cert=None,
                                             ssl_client_key=None)
        self.assertEquals(result, {"url": "https://fake.com:8200",
                                   "verify": True})

    def test_make_client_kwargs_ssl_ca_cert(self):
        backend = VaultAuthenticationBackend(vault_url="https://fake.com:8200",
                                             auth_method="app_role")

        # ensure ca cert path is set when specified
        result = backend._make_client_kwargs(vault_url="https://fake.com:8200",
                                             ssl_verify=True,
                                             ssl_ca_cert="/path/to/ssl_ca.crt",
                                             ssl_client_cert=None,
                                             ssl_client_key=None)
        self.assertEquals(result, {"url": "https://fake.com:8200",
                                   "verify": "/path/to/ssl_ca.crt"})

        # ensure ca cert path is set when specified, even when ssl_verify
        # is set to False
        result = backend._make_client_kwargs(vault_url="https://fake.com:8200",
                                             ssl_verify=False,
                                             ssl_ca_cert="/path/to/ssl_ca.crt",
                                             ssl_client_cert=None,
                                             ssl_client_key=None)
        self.assertEquals(result, {"url": "https://fake.com:8200",
                                   "verify": "/path/to/ssl_ca.crt"})

    def test_make_client_kwargs_ssl_client_cert_only(self):
        backend = VaultAuthenticationBackend(vault_url="https://fake.com:8200",
                                             auth_method="app_role")

        # test only setting ssl_client_cert
        result = backend._make_client_kwargs(vault_url="https://fake.com:8200",
                                             ssl_verify=True,
                                             ssl_ca_cert=None,
                                             ssl_client_cert="/path/to/ssl_client.pem",
                                             ssl_client_key=None)
        self.assertEquals(result, {"url": "https://fake.com:8200",
                                   "verify": True,
                                   "cert": "/path/to/ssl_client.pem"})

    def test_make_client_kwargs_ssl_client_cert_and_client_key(self):
        backend = VaultAuthenticationBackend(vault_url="https://fake.com:8200",
                                             auth_method="app_role")

        result = backend._make_client_kwargs(vault_url="https://fake.com:8200",
                                             ssl_verify=True,
                                             ssl_ca_cert=None,
                                             ssl_client_cert="/path/to/ssl_client.crt",
                                             ssl_client_key="/path/to/ssl_client.key")
        self.assertEquals(result, {"url": "https://fake.com:8200",
                                   "verify": True,
                                   "cert": ("/path/to/ssl_client.crt",
                                            "/path/to/ssl_client.key")})

    def test_make_client_kwargs_ssl_client_key_only(self):
        backend = VaultAuthenticationBackend(vault_url="https://fake.com:8200",
                                             auth_method="app_role")

        result = backend._make_client_kwargs(vault_url="https://fake.com:8200",
                                             ssl_verify=True,
                                             ssl_ca_cert=None,
                                             ssl_client_cert=None,
                                             ssl_client_key="/path/to/ssl_client.key")
        self.assertEquals(result, {"url": "https://fake.com:8200",
                                   "verify": True})

    @mock.patch("requests.Session", side_effect=_mock_vault_session)
    def test_authenticate_app_id(self, mock_session):
        backend = VaultAuthenticationBackend(vault_url="https://fake.com:8200",
                                             auth_method="app_id")

        self.assertTrue(backend.authenticate("good", "password"))
        self.assertFalse(backend.authenticate("bad", "password"))

    @mock.patch("requests.Session", side_effect=_mock_vault_session)
    def test_authenticate_app_role(self, mock_session):
        backend = VaultAuthenticationBackend(vault_url="https://fake.com:8200",
                                             auth_method="app_role")

        self.assertTrue(backend.authenticate("good", "password"))
        self.assertFalse(backend.authenticate("bad", "password"))

    @mock.patch("hvac.Client.is_authenticated")
    @mock.patch("hvac.Client.auth_aws_iam")
    @mock.patch("requests.Session", side_effect=_mock_vault_session)
    def test_authenticate_aws(self, mock_session, mock_aws_iam, mock_is_authenticated):
        def _mock_auth_aws(*args, **kwargs):
            if args[0] == "good":
                return True
            else:
                raise Exception("bad auth")
        mock_aws_iam.side_effect = _mock_auth_aws
        mock_is_authenticated.side_effect = [True, False]

        backend = VaultAuthenticationBackend(vault_url="https://fake.com:8200",
                                             auth_method="aws")

        self.assertTrue(backend.authenticate("good", "password"))
        self.assertFalse(backend.authenticate("bad", "password"))

    @mock.patch("requests.Session", side_effect=_mock_vault_session)
    def test_authenticate_azure(self, mock_session):
        backend = VaultAuthenticationBackend(vault_url="https://fake.com:8200",
                                             auth_method="azure")

        self.assertTrue(backend.authenticate("good", "password"))
        self.assertFalse(backend.authenticate("bad", "password"))

    @mock.patch("requests.Session", side_effect=_mock_vault_session)
    def test_authenticate_gcp(self, mock_session):
        backend = VaultAuthenticationBackend(vault_url="https://fake.com:8200",
                                             auth_method="gcp")

        self.assertTrue(backend.authenticate("good", "password"))
        self.assertFalse(backend.authenticate("bad", "password"))

    @mock.patch("requests.Session", side_effect=_mock_vault_session)
    def test_authenticate_github(self, mock_session):
        backend = VaultAuthenticationBackend(vault_url="https://fake.com:8200",
                                             auth_method="github")

        self.assertTrue(backend.authenticate("user_doesnt_matter_for_github_auth", "good"))
        self.assertFalse(backend.authenticate("user_doesnt_matter_for_github_auth", "bad"))

    @mock.patch("requests.Session", side_effect=_mock_vault_session)
    def test_authenticate_kubernetes(self, mock_session):
        backend = VaultAuthenticationBackend(vault_url="https://fake.com:8200",
                                             auth_method="kubernetes")

        self.assertTrue(backend.authenticate("good", "password"))
        self.assertFalse(backend.authenticate("bad", "password"))

    @mock.patch("requests.Session", side_effect=_mock_vault_session)
    def test_authenticate_ldap(self, mock_session):
        backend = VaultAuthenticationBackend(vault_url="https://fake.com:8200",
                                             auth_method="ldap")

        self.assertTrue(backend.authenticate("good", "password"))
        self.assertFalse(backend.authenticate("bad", "password"))

    @mock.patch("requests.Session", side_effect=_mock_vault_session)
    def test_authenticate_okta(self, okta):
        backend = VaultAuthenticationBackend(vault_url="https://fake.com:8200",
                                             auth_method="okta")

        self.assertTrue(backend.authenticate("good", "password"))
        self.assertFalse(backend.authenticate("bad", "password"))

    @mock.patch("requests.Session", side_effect=_mock_vault_session)
    def test_authenticate_radius(self, okta):
        backend = VaultAuthenticationBackend(vault_url="https://fake.com:8200",
                                             auth_method="radius")

        self.assertTrue(backend.authenticate("good", "password"))
        self.assertFalse(backend.authenticate("bad", "password"))

    @mock.patch("requests.Session", side_effect=_mock_vault_session)
    def test_authenticate_token(self, okta):
        backend = VaultAuthenticationBackend(vault_url="https://fake.com:8200",
                                             auth_method="token")

        self.assertTrue(backend.authenticate("username_doesnt_matter_for_token_auth", "good_token"))
        self.assertFalse(backend.authenticate("username_doesnt_matter_for_token_auth", "bad_token"))

    @mock.patch("requests.Session", side_effect=_mock_vault_session)
    def test_authenticate_userpass(self, okta):
        backend = VaultAuthenticationBackend(vault_url="https://fake.com:8200",
                                             auth_method="userpass")

        self.assertTrue(backend.authenticate("good", "password"))
        self.assertFalse(backend.authenticate("bad", "password"))

if __name__ == "__main__":
    sys.exit(unittest2.main())

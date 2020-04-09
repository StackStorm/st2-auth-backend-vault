import hvac
import os
import unittest

from st2auth_vault_backend.vault import VaultAuthenticationBackend

VAULT_URL = os.environ.get("VAULT_URL", "http://127.0.0.1:8200")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "st2token")


class BaseIntegrationTestCase(unittest.TestCase):

    def create_client(self, **kwargs):
        vault_url = VAULT_URL
        if "vault_url" in kwargs:
            vault_url = kwargs['vault_url']
            del kwargs['vault_url']

        vault_token = VAULT_TOKEN
        if "vault_token" in kwargs:
            vault_token = kwargs['vault_token']
            del kwargs['vault_token']

        return hvac.Client(url=vault_url, token=vault_token, **kwargs)

    def create_backend(self, auth_method, **kwargs):
        vault_url = VAULT_URL
        if "vault_url" in kwargs:
            vault_url = kwargs['vault_url']
            del kwargs['vault_url']
        return VaultAuthenticationBackend(vault_url=vault_url,
                                          auth_method=auth_method,
                                          **kwargs)

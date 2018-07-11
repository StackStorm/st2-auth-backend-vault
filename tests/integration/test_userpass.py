import mock
import os
import unittest

from base import BaseIntegrationTestCase


class TestVaultUserPass(BaseIntegrationTestCase):

    def setUp(self):
        super(TestVaultUserPass, self).setUp()
        client = self.create_client()
        client.enable_auth_backend('userpass')

    def tearDown(self):
        super(TestVaultUserPass, self).tearDown()
        client = self.create_client()
        client.disable_auth_backend('userpass')

    def test_userpass_good(self):
        client = self.create_client()
        client.write('auth/userpass/users/testuser',
                     password="xxx")
        backend = self.create_backend('userpass')

        result = backend.authenticate('testuser', 'xxx')
        self.assertEquals(result, True)

    def test_userpass_fail(self):
        backend = self.create_backend('userpass')
        result = backend.authenticate('junkuser', 'badpassword')
        self.assertEquals(result, False)

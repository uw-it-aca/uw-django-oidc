from django.test import TestCase
from unittest.mock import patch
from uw_oidc.jwks import UW_JWKS, JwksFetchError, JwksDataError


class TestUW_JWKS(TestCase):
    def setUp(self):
        self.jwks = UW_JWKS()

    def test_get_public_key(self):
        pass

    def test_get_jwks(self):
        pass

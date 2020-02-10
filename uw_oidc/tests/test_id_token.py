from django.test import TestCase
from django.conf import settings
from django.test.client import RequestFactory
from uw_oidc.id_token import get_payload_from_token, get_token_leeway


class TestIdToken(TestCase):

    def test_get_payload_from_token(self):
        with self.settings(TOKEN_ISSUER="uwidp",
                           TOKEN_AUDIENCE="myuw"):
            pass

    def test_get_token_leeway(self):
        with self.settings(TOKEN_LEEWAY=3):
            self.assertEqual(get_token_leeway(), 3)

from django.test import TestCase
from django.conf import settings
from django.test.client import RequestFactory
from uw_oidc.middleware import IDTokenAuthenticationMiddleware


class TestMiddleware(TestCase):
    def test_process_view(self):
        pass

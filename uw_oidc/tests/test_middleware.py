from django.test import TestCase
from django.conf import settings
from django.test.client import RequestFactory
from uw_oidc.middleware import (
    IdtokenValidationMiddleware, get_authorization_header,
    match_original_userid)


class TestMiddleware(TestCase):
    def test_process_view(self):
        pass

    def test_get_authorization_header(self):
        pass

    def match_original_userid(self):
        pass

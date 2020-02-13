from django.test import TestCase
from django.contrib.auth.models import AnonymousUser, User
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.exceptions import ImproperlyConfigured
from django.test.client import RequestFactory
from uw_oidc.middleware import IDTokenAuthenticationMiddleware
from uw_oidc.exceptions import InvalidTokenError
import mock


class TestMiddleware(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def create_request(self, auth_token=None):
        request = self.factory.get('/', HTTP_AUTHORIZATION=auth_token)
        request.user = AnonymousUser()
        SessionMiddleware().process_request(request)
        request.session.save()
        return request

    def test_process_view_missing_session(self):
        request = self.factory.get('/')
        middleware = IDTokenAuthenticationMiddleware(request)
        self.assertRaises(
            ImproperlyConfigured, middleware.process_view, request,
            None, None, None)

    def test_process_view_invalid_token(self):
        # Invalid token
        request = self.create_request(auth_token='abc')
        middleware = IDTokenAuthenticationMiddleware(request)
        response = middleware.process_view(request, None, None, None)
        self.assertEqual(response.reason_phrase,
                         'Invalid token: Not enough segments')

    @mock.patch('uw_oidc.middleware.username_from_token')
    def test_process_view_invalid_username(self, mock_fn):
        mock_fn.return_value = ''
        request = self.create_request(auth_token='abc')
        middleware = IDTokenAuthenticationMiddleware(request)
        response = middleware.process_view(request, None, None, None)
        self.assertEqual(response.reason_phrase,
                         'Invalid token: Missing username')

    def test_clean_username(self):
        request = self.create_request()
        middleware = IDTokenAuthenticationMiddleware(request)
        self.assertRaises(InvalidTokenError, middleware.clean_username, None)
        self.assertRaises(InvalidTokenError, middleware.clean_username, '')
        self.assertEqual(middleware.clean_username('javerage'), 'javerage')
        self.assertEqual(middleware.clean_username('j@test.edu'), 'j')
        self.assertEqual(middleware.clean_username('j@test@edu'), 'j')

from django.test import TestCase, override_settings
from django.contrib.auth import authenticate, login
from django.contrib.auth.middleware import AuthenticationMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.exceptions import ImproperlyConfigured
from django.test.client import RequestFactory
from unittest.mock import patch
from uw_oidc.middleware import IDTokenAuthenticationMiddleware
from uw_oidc.exceptions import InvalidTokenError


@override_settings(AUTHENTICATION_BACKENDS=[
    'django.contrib.auth.backends.RemoteUserBackend'])
class TestMiddleware(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def create_unauthenticated_request(self, auth_token=None):
        if auth_token is not None:
            request = self.factory.get('/', HTTP_AUTHORIZATION=auth_token)
        else:
            request = self.factory.get('/')
        SessionMiddleware().process_request(request)
        AuthenticationMiddleware().process_request(request)
        return request

    def create_authenticated_request(self, auth_token=None):
        request = self.create_unauthenticated_request(auth_token)
        user = authenticate(request, remote_user='javerage')
        login(request, user)
        return request

    def test_process_view_missing_session(self):
        request = self.factory.get('/')
        middleware = IDTokenAuthenticationMiddleware()
        self.assertRaises(
            ImproperlyConfigured, middleware.process_view, request,
            None, None, None)

    def test_process_view_invalid_token(self):
        request = self.create_unauthenticated_request(auth_token='abc')
        middleware = IDTokenAuthenticationMiddleware()
        response = middleware.process_view(request, None, None, None)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.reason_phrase,
                         'Invalid token: Not enough segments')

    @patch('uw_oidc.middleware.username_from_token')
    @override_settings(TOKEN_ERR_CODE=402)
    def test_process_view_invalid_username(self, mock_fn):
        mock_fn.return_value = ''

        request = self.create_unauthenticated_request(auth_token='abc')
        middleware = IDTokenAuthenticationMiddleware()
        response = middleware.process_view(request, None, None, None)
        self.assertEqual(response.status_code, 402)
        self.assertEqual(response.reason_phrase,
                         'Invalid token: Missing username')

    @patch('uw_oidc.middleware.username_from_token')
    @override_settings(TOKEN_ERR_CODE=402)
    def test_process_view_username_mismatch(self, mock_fn):
        mock_fn.return_value = 'bill'

        request = self.create_authenticated_request(auth_token='abc')
        middleware = IDTokenAuthenticationMiddleware()
        response = middleware.process_view(request, None, None, None)
        self.assertEqual(response.status_code, 402)
        self.assertEqual(response.reason_phrase,
                         'Invalid token: Username mismatch')

    @patch('uw_oidc.middleware.username_from_token')
    def test_process_view_already_authenticated(self, mock_fn):
        mock_fn.return_value = 'javerage'

        request = self.create_authenticated_request(auth_token='abc')
        middleware = IDTokenAuthenticationMiddleware()
        response = middleware.process_view(request, None, None, None)
        self.assertEqual(response, None)

    @patch('uw_oidc.middleware.username_from_token')
    def test_process_view_authenticate(self, mock_fn):
        mock_fn.return_value = 'javerage'

        request = self.create_unauthenticated_request(auth_token='abc')
        self.assertEqual(request.user.is_authenticated, False)

        middleware = IDTokenAuthenticationMiddleware()
        response = middleware.process_view(request, None, None, None)

        # Check that user has been logged in, and token added to session
        self.assertEqual(response, None)
        self.assertEqual(request.user.is_authenticated, True)
        self.assertEqual(
            request.session.get(middleware.TOKEN_SESSION_KEY), 'abc')

    def test_process_view_invalid_session(self):
        request = self.create_authenticated_request()

        middleware = IDTokenAuthenticationMiddleware()
        request.session[middleware.TOKEN_SESSION_KEY] = 'abc'

        response = middleware.process_view(request, None, None, None)

        # Check that user has been logged out, and session token deleted
        self.assertEqual(response, None)
        self.assertEqual(request.user.is_authenticated, False)
        with self.assertRaises(KeyError) as raises:
            request.session[middleware.TOKEN_SESSION_KEY]

    def test_clean_username(self):
        request = self.create_unauthenticated_request()
        middleware = IDTokenAuthenticationMiddleware()
        self.assertRaises(InvalidTokenError, middleware.clean_username, None)
        self.assertRaises(InvalidTokenError, middleware.clean_username, '')
        self.assertEqual(middleware.clean_username('javerage'), 'javerage')
        self.assertEqual(middleware.clean_username('j@test.edu'), 'j')
        self.assertEqual(middleware.clean_username('j@test@edu'), 'j')

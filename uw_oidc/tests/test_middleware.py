from django.test import TestCase, override_settings
from django.contrib import auth
from django.contrib.auth.models import User
from django.contrib.auth.middleware import AuthenticationMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.exceptions import ImproperlyConfigured
from django.test.client import RequestFactory
from uw_oidc.middleware import IDTokenAuthenticationMiddleware
from uw_oidc.exceptions import InvalidTokenError
import mock


@override_settings(AUTHENTICATION_BACKENDS=[
    'django.contrib.auth.backends.RemoteUserBackend'])
class TestMiddleware(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username='javerage')

    def tearDown(self):
        User.objects.all().delete()

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
        user = auth.authenticate(request, remote_user='javerage')
        auth.login(request, user)
        return request

    def test_process_view_missing_session(self):
        request = self.factory.get('/')
        middleware = IDTokenAuthenticationMiddleware(request)
        self.assertRaises(
            ImproperlyConfigured, middleware.process_view, request,
            None, None, None)

    def test_process_view_invalid_token(self):
        request = self.create_unauthenticated_request(auth_token='abc')
        middleware = IDTokenAuthenticationMiddleware(request)
        response = middleware.process_view(request, None, None, None)
        self.assertEqual(response.reason_phrase,
                         'Invalid token: Not enough segments')

    @mock.patch('uw_oidc.middleware.username_from_token')
    def test_process_view_invalid_username(self, mock_fn):
        mock_fn.return_value = ''

        request = self.create_unauthenticated_request(auth_token='abc')
        middleware = IDTokenAuthenticationMiddleware(request)
        response = middleware.process_view(request, None, None, None)
        self.assertEqual(response.reason_phrase,
                         'Invalid token: Missing username')

    @mock.patch('uw_oidc.middleware.username_from_token')
    def test_process_view_username_mismatch(self, mock_fn):
        mock_fn.return_value = 'bill'

        request = self.create_authenticated_request(auth_token='abc')
        middleware = IDTokenAuthenticationMiddleware(request)
        response = middleware.process_view(request, None, None, None)
        self.assertEqual(response.reason_phrase,
                         'Invalid token: Username mismatch')

    @mock.patch('uw_oidc.middleware.username_from_token')
    def test_process_view_successful_login(self, mock_fn):
        mock_fn.return_value = 'javerage'

        request = self.create_unauthenticated_request(auth_token='abc')
        self.assertEqual(request.user.is_authenticated, False)

        middleware = IDTokenAuthenticationMiddleware(request)
        response = middleware.process_view(request, None, None, None)

        # Check that user has been logged in, and token added to session
        self.assertEqual(response, None)
        self.assertEqual(request.user.is_authenticated, True)
        self.assertEqual(
            request.session.get(middleware.TOKEN_SESSION_KEY), 'abc')

    def test_process_view_invalid_session(self):
        request = self.create_authenticated_request()

        middleware = IDTokenAuthenticationMiddleware(request)
        request.session[middleware.TOKEN_SESSION_KEY] = 'abc'

        response = middleware.process_view(request, None, None, None)

        # Check that user has been logged out, and session token deleted
        self.assertEqual(response, None)
        self.assertEqual(request.user.is_authenticated, False)
        with self.assertRaises(KeyError) as raises:
            request.session[middleware.TOKEN_SESSION_KEY]

    def test_clean_username(self):
        request = self.create_unauthenticated_request()
        middleware = IDTokenAuthenticationMiddleware(request)
        self.assertRaises(InvalidTokenError, middleware.clean_username, None)
        self.assertRaises(InvalidTokenError, middleware.clean_username, '')
        self.assertEqual(middleware.clean_username('javerage'), 'javerage')
        self.assertEqual(middleware.clean_username('j@test.edu'), 'j')
        self.assertEqual(middleware.clean_username('j@test@edu'), 'j')

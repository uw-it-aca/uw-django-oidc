from django.test import TestCase, override_settings
from django.contrib.auth import authenticate, login
from django.contrib.auth.middleware import AuthenticationMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.exceptions import ImproperlyConfigured
from django.test.client import RequestFactory
from unittest.mock import patch
from uw_oidc.middleware import (
    IDTokenAuthenticationMiddleware, UWIdPToken, InvalidTokenError)


@override_settings(UW_TOKEN_AUDIENCE='myid',
                   UW_TOKEN_SESSION_AGE=60,
                   AUTHENTICATION_BACKENDS=[
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

    def create_authenticated_request(self, auth_token=''):
        request = self.create_unauthenticated_request(auth_token)
        user = authenticate(request, remote_user='javerage')
        login(request, user)
        if auth_token is not None:
            request.session['uw_oidc_idtoken'] = auth_token
        return request

    def test_process_view_missing_session(self):
        request = self.factory.get('/')
        middleware = IDTokenAuthenticationMiddleware()
        self.assertRaises(
            ImproperlyConfigured, middleware.process_view, request,
            None, None, None)

    @patch.object(UWIdPToken, 'username_from_token')
    def test_process_view_invalid_token(self, mock_username_from_token):
        request = self.create_unauthenticated_request(auth_token='')
        middleware = IDTokenAuthenticationMiddleware()
        mock_username_from_token.side_effect = InvalidTokenError(
            'Not enough segments')
        response = middleware.process_view(request, None, None, None)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.reason_phrase,
                         'InvalidTokenError: Not enough segments')

    @patch.object(UWIdPToken, 'username_from_token')
    def test_process_view_expired_token(self, mock_username_from_token):
        request = self.create_unauthenticated_request(auth_token='')
        middleware = IDTokenAuthenticationMiddleware()
        mock_username_from_token.side_effect = InvalidTokenError(
            'ExpiredSignatureError')
        response = middleware.process_view(request, None, None, None)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.reason_phrase,
                         'InvalidTokenError: ExpiredSignatureError')

    @patch.object(UWIdPToken, 'username_from_token', return_value='')
    def test_process_view_invalid_username(self, mock_fn):
        request = self.create_unauthenticated_request(auth_token='')
        middleware = IDTokenAuthenticationMiddleware()
        response = middleware.process_view(request, None, None, None)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.reason_phrase,
                         'InvalidTokenError: Missing username')

    def test_process_view_already_authenticated(self):
        request = self.create_authenticated_request()
        middleware = IDTokenAuthenticationMiddleware()
        response = middleware.process_view(request, None, None, None)
        self.assertEqual(response, None)

    @patch.object(UWIdPToken, 'username_from_token', return_value='javerage')
    def test_process_view_authenticate(self, mock_fn):
        request = self.create_unauthenticated_request(auth_token='abc')

        self.assertEqual(request.user.is_authenticated, False)
        middleware = IDTokenAuthenticationMiddleware()
        response = middleware.process_view(request, None, None, None)
        self.assertEqual(response, None)

        # Check that user has been logged in
        self.assertEqual(request.user.is_authenticated, True)
        # token added to session
        self.assertEqual(
            request.session.get(middleware.TOKEN_SESSION_KEY), 'abc')
        self.assertEqual(
            request.session.get(middleware.USER_KEY), 'javerage')
        self.assertEqual(
            request.session.get_expiry_age(), 60)

    def test_authed_session_req_wo_token(self):
        request = self.create_authenticated_request()
        middleware = IDTokenAuthenticationMiddleware()
        del request.META['HTTP_AUTHORIZATION']
        response = middleware.process_view(request, None, None, None)
        self.assertEqual(response, None)
        self.assertTrue(request.user.is_authenticated)
        self.assertIsNotNone(request.session[middleware.TOKEN_SESSION_KEY])

    def test_clean_username(self):
        request = self.create_unauthenticated_request()
        middleware = IDTokenAuthenticationMiddleware()
        self.assertRaises(InvalidTokenError, middleware.clean_username, None)
        self.assertRaises(InvalidTokenError, middleware.clean_username, '')
        self.assertEqual(middleware.clean_username('javerage'), 'javerage')
        self.assertEqual(middleware.clean_username('j@test.edu'), 'j')
        self.assertEqual(middleware.clean_username('j@test@edu'), 'j')

# Copyright 2025 UW-IT, University of Washington
# SPDX-License-Identifier: Apache-2.0

import mock
from django.http import HttpResponse
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

    def wrap_middleware(self):
        """Return middleware with a simple get_response function."""
        return IDTokenAuthenticationMiddleware(lambda req: HttpResponse("OK"))

    def create_unauthenticated_request(self, auth_token=None):
        request = self.factory.get('/', HTTP_AUTHORIZATION=auth_token)
        get_response = mock.MagicMock()
        SessionMiddleware(get_response).process_request(request)
        AuthenticationMiddleware(get_response).process_request(request)
        return request

    def create_authenticated_request(self, auth_token=''):
        request = self.create_unauthenticated_request(auth_token)
        user = authenticate(request, remote_user='javerage')
        login(request, user)
        if auth_token is not None:
            request.session['uw_oidc_idtoken'] = auth_token
        return request

    def test_missing_session(self):
        request = self.factory.get('/')
        middleware = self.wrap_middleware()
        with self.assertRaises(ImproperlyConfigured):
            middleware(request)

    @patch.object(UWIdPToken, 'username_from_token')
    def test_invalid_token(self, mock_username_from_token):
        request = self.create_unauthenticated_request(auth_token='bad')
        middleware = self.wrap_middleware()
        mock_username_from_token.side_effect = InvalidTokenError(
            'Not enough segments')
        response = middleware(request)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.reason_phrase,
                         'InvalidTokenError: Not enough segments')

    @patch.object(UWIdPToken, 'username_from_token')
    def test_expired_token(self, mock_username_from_token):
        request = self.create_unauthenticated_request(auth_token='expired')
        middleware = self.wrap_middleware()
        mock_username_from_token.side_effect = InvalidTokenError(
            'ExpiredSignatureError')
        response = middleware(request)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.reason_phrase,
                         'InvalidTokenError: ExpiredSignatureError')

    @patch.object(UWIdPToken, 'username_from_token', return_value='')
    def test_invalid_username(self, mock_fn):
        request = self.create_unauthenticated_request(auth_token="sometoken")
        middleware = self.wrap_middleware()
        response = middleware(request)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.reason_phrase,
                         'InvalidTokenError: Missing username')

    def test_already_authenticated(self):
        request = self.create_authenticated_request()
        middleware = self.wrap_middleware()
        response = middleware(request)
        self.assertEqual(response.status_code, 200)

    @patch.object(UWIdPToken, 'username_from_token', return_value='javerage')
    def test_authenticate_with_token(self, mock_fn):
        request = self.create_unauthenticated_request(auth_token="abc")
        self.assertFalse(request.user.is_authenticated)
        middleware = self.wrap_middleware()
        response = middleware(request)
        self.assertEqual(response.status_code, 200)

        # Check that user has been logged in
        self.assertTrue(request.user.is_authenticated)
        self.assertEqual(
            request.session.get(middleware.TOKEN_SESSION_KEY), "abc")
        self.assertEqual(
            request.session.get(middleware.USER_KEY), 'javerage')
        self.assertEqual(request.session.get_expiry_age(), 60)

    def test_authed_session_request_without_token(self):
        request = self.create_authenticated_request()
        middleware = self.wrap_middleware()
        del request.META['HTTP_AUTHORIZATION']
        response = middleware(request)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(request.user.is_authenticated)
        self.assertIsNotNone(request.session[middleware.TOKEN_SESSION_KEY])

    def test_clean_username(self):
        middleware = self.wrap_middleware()
        with self.assertRaises(InvalidTokenError):
            middleware.clean_username(None)
        with self.assertRaises(InvalidTokenError):
            middleware.clean_username("")
        self.assertEqual(middleware.clean_username('javerage'), 'javerage')
        self.assertEqual(middleware.clean_username('j@test.edu'), 'j')
        self.assertEqual(middleware.clean_username('j@test@edu'), 'j')

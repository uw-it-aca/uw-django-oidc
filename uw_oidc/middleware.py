# Copyright 2025 UW-IT, University of Washington
# SPDX-License-Identifier: Apache-2.0

import logging
from django.conf import settings
from django.contrib import auth
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from uw_oidc.exceptions import InvalidTokenError
from uw_oidc.id_token import UWIdPToken
from uw_oidc.logger import log_info

logger = logging.getLogger(__name__)


class IDTokenAuthenticationMiddleware:
    """
    Supports ID Token (issued by UW OIDC provider)
    based request authentication for specified clients.
    """
    TOKEN_SESSION_KEY = 'uw_oidc_idtoken'
    USER_KEY = '_uw_original_user'

    def __init__(self, get_response=None):
        self.get_response = get_response

    def __call__(self, request):
        # Ensure sessions are available
        if not hasattr(request, 'session'):
            raise ImproperlyConfigured(
                "This authentication middleware requires session middleware. "
                "Insert 'django.contrib.sessions.middleware.SessionMiddleware'"
                " before 'uw_oidc.middleware.IDTokenAuthenticationMiddleware'."
            )

        if 'HTTP_AUTHORIZATION' in request.META:
            try:
                if not request.user.is_authenticated:
                    # Conduct the authentication
                    token = request.META['HTTP_AUTHORIZATION'].removeprefix(
                        "Bearer ")

                    username = self.clean_username(
                        UWIdPToken().username_from_token(token))

                    user = auth.authenticate(request, remote_user=username)
                    if user:
                        auth.login(request, user)

                        # Set persistent session length in seconds
                        request.session.set_expiry(
                            getattr(settings, 'UW_TOKEN_SESSION_AGE', 28800))

                        request.session[self.TOKEN_SESSION_KEY] = token
                        request.session[self.USER_KEY] = username

                        log_info(
                            logger,
                            {
                                'msg': "Login token-based session",
                                'user': username,
                                'expiry_age': request.session.get_expiry_age(),
                                'url': request.META.get('REQUEST_URI')})
                else:
                    # honor existing session
                    log_info(
                        logger,
                        {
                            'msg': "Active session exists",
                            'user': request.user.username,
                            'expiry_age': request.session.get_expiry_age()})

            except InvalidTokenError as ex:
                return HttpResponse(status=401, reason=str(ex))
        return self.get_response(request)

    def clean_username(self, username):
        if username is None or not len(username):
            raise InvalidTokenError('Missing username')

        try:
            (username, _) = username.split('@', 1)
        except ValueError:
            pass
        return username

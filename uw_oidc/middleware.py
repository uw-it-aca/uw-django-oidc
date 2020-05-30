import logging
from django.conf import settings
from django.contrib import auth
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from django.utils.deprecation import MiddlewareMixin
from uw_oidc.exceptions import InvalidTokenError
from uw_oidc.id_token import UWIdPToken
from uw_oidc.logger import log_err, log_info

logger = logging.getLogger(__name__)


class IDTokenAuthenticationMiddleware(MiddlewareMixin):
    """
    Supports ID Token (issued by UW OIDC provider)
    based request authentication for specified clients.
    """
    TOKEN_SESSION_KEY = 'uw_oidc_idtoken'
    USER_KEY = '_uw_original_user'

    def __init__(self, get_response=None):
        self.get_response = get_response

    def process_view(self, request, view_func, view_args, view_kwargs):
        if not hasattr(request, 'session'):
            raise ImproperlyConfigured(
                'This authentication middleware requires session middleware '
                'to be installed. Edit your MIDDLEWARE setting to insert '
                '"django.contrib.sessions.middleware.SessionMiddleware" '
                'before "uw_oidc.middleware.IDTokenAuthenticationMiddleware".')

        if 'HTTP_AUTHORIZATION' in request.META:
            try:
                if request.user.is_authenticated:
                    # honor the existing session
                    return None

                # We are seeing this user for the first time in this
                # session, attempt to authenticate the user.
                token = request.META['HTTP_AUTHORIZATION'].replace(
                    'Bearer ', '', 1)
                username = self.clean_username(
                    UWIdPToken().username_from_token(token))

                user = auth.authenticate(request, remote_user=username)
                if user:
                    # Set logged-in user in request.user
                    auth.login(request, user)

                    # Set persistent session length in seconds
                    request.session.set_expiry(
                        getattr(settings, 'UW_TOKEN_SESSION_AGE', 28800))

                    request.session[self.TOKEN_SESSION_KEY] = token
                    request.session[self.USER_KEY] = username

                    log_info(logger, {'msg': "Login token-based session",
                                      'user': username,
                                      'url': request.META.get('REQUEST_URI')})
            except InvalidTokenError as ex:
                return HttpResponse(status=401, reason=str(ex))
        return None

    def clean_username(self, username):
        if username is None or not len(username):
            raise InvalidTokenError('Missing username')

        try:
            (username, domain) = username.split('@', 1)
        except ValueError:
            pass

        return username

from django.contrib import auth
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from uw_oidc.id_token import username_from_token
from uw_oidc.exceptions import InvalidTokenError


class IDTokenAuthenticationMiddleware:
    """
    Supports ID Token (issued by UW OIDC provider)
    based request authentication for specified clients.
    """
    TOKEN_SESSION_KEY = 'uw_oidc_idtoken'

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
            auth_token = request.META['HTTP_AUTHORIZATION']

            try:
                username = self.clean_username(username_from_token(auth_token))

                if request.user.is_authenticated:
                    if request.user.get_username() != username:
                        # An authenticated user is associated with the request,
                        # but it does not match the user in the token.
                        raise InvalidTokenError('Username mismatch')
                else:
                    # We are seeing this user for the first time in this
                    # session, attempt to authenticate the user.
                    user = auth.authenticate(request, remote_user=username)
                    if user:
                        # User is valid.  Set request.user and persist user
                        # in the session by logging the user in.
                        auth.login(request, user)
                        request.session[self.TOKEN_SESSION_KEY] = auth_token

            except InvalidTokenError as ex:
                return HttpResponse(status=401,
                                    reason='Invalid token: {}'.format(ex))
        else:
            if (request.user.is_authenticated and
                    self.TOKEN_SESSION_KEY in request.session):
                # The user is authenticated with a token in session, but the
                # request does not contain a token, the session is invalid.
                del request.session[self.TOKEN_SESSION_KEY]
                auth.logout(request)

        return None

    def clean_username(self, username):
        if username is None or not len(username):
            raise InvalidTokenError('Missing username')

        try:
            (username, domain) = username.split('@', 1)
        except ValueError:
            pass

        return username

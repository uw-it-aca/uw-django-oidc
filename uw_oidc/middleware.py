from django.conf import settings
from django.contrib.auth import authenticate, login, logout, load_backend
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from uw_oidc.id_token import get_payload_from_token, InvalidTokenError


class IDTokenAuthenticationMiddleware:
    """
    Supports ID Token (issued by UW OIDC provider)
    based request authentication for specified clients.
    """
    def __init__(self, get_response=None):
        self.get_response = get_response

    def process_view(self, request, view_func, view_args, view_kwargs):
        if not hasattr(request, 'session'):
            raise ImproperlyConfigured(
                'This authentication middleware requires session middleware '
                'to be installed. Edit your MIDDLEWARE setting to insert '
                '"django.contrib.sessions.middleware.SessionMiddleware" '
                'before "uw_oidc.middleware.IDTokenAuthenticationMiddleware".')

        if is_oidc_client(request):
            json_web_token = request.META.get('HTTP_AUTHORIZATION')

            session_key = getattr(
                settings, 'OIDC_TOKEN_SESSION_KEY', 'oidcIdToken')
            if (request.user.is_authenticated and json_web_token and
                    json_web_token == request.session.get(session_key)):
                # The user is authenticated, and the token in session matches
                # the one in the request
                return None

            try:
                payload = get_payload_from_token(json_web_token)
                username = self.clean_username(payload.get('sub'), request)

                if request.user.is_authenticated:
                    if request.user.get_username() != username:
                        # An authenticated user is associated with the request,
                        # but it does not match the user in the token.
                        logout(request)
                else:
                    # We are seeing this user for the first time in this
                    # session, attempt to authenticate the user.
                    user = authenticate(request, remote_user=username)
                    if user:
                        # User is valid.  Set request.user and persist user
                        # in the session by logging the user in.
                        login(request, user)
                        request.session[session_key] = json_web_token

            except InvalidTokenError as ex:
                return HttpResponse(status=401, reason=ex)

        return None

    def clean_username(self, username, request):
        backend_str = request.session[auth.BACKEND_SESSION_KEY]
        backend = auth.load_backend(backend_str)
        try:
            username = backend.clean_username(username)
        except AttributeError:  # Backend has no clean_username method.
            pass

        try:
            # Convert eppn to uwnetid
            # TODO: what about apps that need eppn?
            (username, domain) = username.split('@', 1)
        except ValueError:
            pass

        return username

    def is_oidc_client(self, request):
        oidc_ua = getattr(settings, 'OIDC_CLIENT_USER_AGENT')
        if oidc_ua:
            return oidc_ua == request.META.get('HTTP_USER_AGENT', '')
        return False
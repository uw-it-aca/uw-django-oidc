from django.conf import settings
from django.contrib.auth import authenticate, login
from django.http import HttpResponse


class MissingTokenException(Exception):
    pass


class MissingUserException(Exception):
    pass


class OIDCAuthenticationMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def process_view(request, view_func, view_args, view_kwargs):
        """
        https://docs.djangoproject.com/en/2.1/topics/http/middleware/#process-view
        """
        if self._is_oidc_client(request):
            try:
                token = self._token_from_request(request)

                if not request.user.is_authenticated:
                    remote_user = self._user_from_token(token)
                    user = authenticate(request, remote_user=remote_user)
                    login(request, user)

                request.session['oidcIDToken'] = token

            except (MissingTokenException, MissingUserException):
                return HttpResponse(status=401)

        return None

    @staticmethod
    def _token_from_request(request):
        token = request.META.get('HTTP_AUTHORIZATION')
        if token is None:
            raise MissingTokenException()
        return token

    @staticmethod
    def _user_from_token(token):
        # TODO
        raise MissingUserException()

    @staticmethod
    def _is_oidc_client(request):
        return (request.META.get('HTTP_USER_AGENT', '') == getattr(
            settings, 'OIDC_CLIENT_USER_AGENT'))

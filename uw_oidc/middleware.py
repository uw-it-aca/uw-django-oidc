from django.conf import settings
from django.http import HttpResponse
from uw_oidc.exceptions import (
    ValidationError, MissingTokenError, UserMismatchError, PyJWTError)
from uw_oidc.id_token import get_payload_from_token


class IdtokenValidationMiddleware:
    """
    Middleware for handling UW OIDC provided authentication ID Token.
    """

    def __init__(self, get_response=None):
        self.get_response = get_response

    def process_view(request, view_func, view_args, view_kwargs):
        if is_oidc_client(request):
            try:
                json_web_token = get_authorization_header(request)
                if json_web_token is None:
                    raise MissingTokenError()

                token_payload = get_payload_from_token(json_web_token)
                # print("TOKEN_PAYLOAD={}".format(token_payload))

                if request.user.is_authenticated:
                    if not match_original_userid(request, token_payload):
                        raise UserMismatchError(token_payload)
                else:
                    create_session_user(request, token_payload)

                set_token_in_session(request, json_web_token)

            except (ValidationError, PyJWTError) as ex:
                return HttpResponse(status=401, reason=str(ex))
        return None


def is_oidc_client(request):
    try:
        header_name = getattr(settings, 'UWOIDC_CLIENT_HEADER', '')
        if header_name and len(header_name):
            hr = request.META.get(header_name)
            return hr and len(client_identifier)
    except Exception:
        pass
    return False


def get_authorization_header(request):
    try:
        return request.META.get('HTTP_AUTHORIZATION')
    except Exception:
        return None


def match_original_userid(request, token_payload):
    userid = token_payload.get("sub")
    if hasattr(request, 'user'):
        username = request.user.username
        if username is not None and len(username):
            try:
                (username, domain) = username.split('@', 1)
            except ValueError as ex:
                pass
            return username
    return userid and username and userid == username


def create_session_user(request, token_payload):
    """
    Authenticate the user for the first time in this session
    Raise: InvalidUserError
    """
    userid = token_payload.get("sub")
    if not is_valid_userid(userid):
        raise InvalidUserError(token_payload)
    user = authenticate(request, remote_user=userid)
    if user is not None:
        request.user = user
        login(request, user)


def set_token_in_session(request, token):
    st_name = getattr(settings, "SESSION_TOKEN_NAME")
    if st_name and len(st_name):
        request.session[st_name] = token

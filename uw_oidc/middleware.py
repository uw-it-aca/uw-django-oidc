from django.http import HttpResponse
from uw_oidc.exceptions import (
    ValidationError, MissingTokenError, UserMismatchError, PyJWTError)
from uw_oidc.id_token import get_payload_from_token
from uw_oidc.session_util import create_session_user, set_token_in_session


class IdtokenValidationMiddleware:
    """
    Middleware for handling UW OIDC provided authentication ID Token.
    """

    def __init__(self, get_response=None):
        self.get_response = get_response

    def process_view(request, view_func, view_args, view_kwargs):
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

            set_token_in_session(request, token)

        except (ValidationError, PyJWTError) as ex:
            return HttpResponse(status=401, reason=str(ex))
        return None


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

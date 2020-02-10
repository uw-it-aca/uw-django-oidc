import re
from uw_oidc import get_session_token_name
from uw_oidc.exceptions import InvalidUserError

VALID_USER_ID = re.compile(r'^[a-z][a-z0-9\-\_\.]{,127}$', re.I)
SESSION_TOKEN_NAME = get_session_token_name()


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


def get_token_from_session(request):
    try:
        return request.session.get(SESSION_TOKEN_NAME)
    except Exception:
        return None


def set_token_in_session(request, token):
    request.session[SESSION_TOKEN_NAME] = token


def is_valid_userid(userid):
    return (userid is not None and
            VALID_USER_ID.match(str(userid)) is not None)

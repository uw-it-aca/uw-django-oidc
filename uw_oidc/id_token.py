from django.conf import settings
from jwt import decode
from jwt.exceptions import PyJWTError
from uw_oidc.dao import get_key
from uw_oidc.exceptions import InvalidTokenError

JWT_OPTIONS = {
    "require_exp": True, "require_iat": True, "verify_signature": True,
    "verify_iat": True, "verify_exp": True, "verify_iss": True,
    "verify_aud": True,
}

IDP_SIGNING_ALGORITHMS = [
    "RS256", "RS384", "RS512", "HS256", "HS384", "HS512", "ES256"
]


def decode_token(token):
    """
    Return the decoded payload from the token, or raise InvalidTokenError if
    not a valid token.
    """
    try:
        return decode(token,
                      options=JWT_OPTIONS,
                      key=get_key(),
                      algorithms=IDP_SIGNING_ALGORITHMS,
                      audience=getattr(settings, "TOKEN_AUDIENCE", ""),
                      issuer=getattr(settings, "TOKEN_ISSUER", ""),
                      leeway=int(getattr(settings, "TOKEN_LEEWAY", 1)))
    except PyJWTError as ex:
        raise InvalidTokenError(ex)


def username_from_token(token):
    return decode_token(token).get("sub")

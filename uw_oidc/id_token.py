from django.conf import settings
from jwt import decode
from jwt.exceptions import PyJWTError
from uw_oidc.exceptions import InvalidTokenError


def get_payload_from_token(token_jwt):
    """
    Return the decoded payload from the token
    raise Exception if not a valid token
    """
    # print("TOKEN_JWT={}".format(token_jwt))
    try:
        return decode(token_jwt,
                      options={
                          "require_exp": True,
                          "require_iat": True,
                          "require_nbf": True,
                          "verify_signature": True,
                          "verify_iat": True,
                          "verify_nbf": True,
                          "verify_exp": True,
                          "verify_iss": True,
                          "verify_aud": True},
                      audience=getattr(settings, "TOKEN_AUDIENCE", ""),
                      issuer=getattr(settings, "TOKEN_ISSUER", ""),
                      leeway=int(getattr(settings, "TOKEN_LEEWAY", 1)))
    except PyJWTError as ex:
        raise InvalidTokenError(ex)

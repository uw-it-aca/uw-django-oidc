from django.conf import settings
import jwt
from uw_oidc import (
    get_token_audience, get_token_issuer, get_token_leeway)
from uw_oidc.exceptions import InvalidTokenException

token_audience = getattr(settings, "TOKEN_AUDIENCE")
token_issuer = getattr(settings, "TOKEN_ISSUER")


def get_payload_from_token(token_jwt):
    """
    Return the decoded payload from the token
    raise Exception if not a valid token
    """
    # print("TOKEN_JWT={}".format(token_jwt))
    return jwt.decode(token,
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
                      verify_expiration=True,
                      audience=token_audience,
                      issuer=token_issuer,
                      leeway=get_token_leeway())


def get_token_leeway():
    # default to 1 minute
    v = getattr(settings, "TOKEN_LEEWAY")
    return int(v) if v else 1

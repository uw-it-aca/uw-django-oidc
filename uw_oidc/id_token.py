import jwt
from uw_oidc.exceptions import InvalidTokenException
from uw_oidc.settings import (
    get_token_audience, get_token_issuer, get_token_leeway)


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
                      audience=get_token_audience(),
                      issuer=get_token_issuer(),
                      leeway=get_token_leeway())

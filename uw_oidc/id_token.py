from django.conf import settings
import jwt


def get_payload_from_token(token_jwt):
    """
    Return the decoded payload from the token
    raise Exception if not a valid token
    """
    # print("TOKEN_JWT={}".format(token_jwt))
    return jwt.decode(token_jwt,
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
                      audience=getattr(settings, "TOKEN_AUDIENCE"),
                      issuer=getattr(settings, "TOKEN_ISSUER"),
                      leeway=get_token_leeway())


def get_token_leeway():
    # default to 1 minute
    v = getattr(settings, "TOKEN_LEEWAY")
    return int(v) if v else 1

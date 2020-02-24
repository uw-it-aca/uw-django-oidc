from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from jwt import decode, get_unverified_header
from jwt.exceptions import PyJWTError, InvalidSignatureError
from uw_oidc.exceptions import (
    InvalidTokenError, InvalidTokenHeader, NoMatchingPublicKey)
from uw_oidc.jwks import UW_JWKS


class UWIdPToken(object):
    JWKS_CLIENT = UW_JWKS()
    JWT_OPTIONS = {
        'require_exp': True, 'require_iat': True,
        'verify_signature': True, 'verify_iat': True, 'verify_exp': True,
        'verify_iss': True, 'verify_aud': True
    }
    SIGNING_ALGORITHMS = [
        'RS256', 'RS384', 'RS512', 'HS256', 'HS384', 'HS512', 'ES256'
    ]

    def __init__(self):
        if (getattr(settings, 'TOKEN_ISSUER') is None or
                getattr(settings, 'TOKEN_AUDIENCE') is None):
            raise ImproperlyConfigured(
                'You must have TOKEN_ISSUER and TOKEN_AUDIENCE'
                ' in your project settings')

    def username_from_token(self, token):
        """
        Raise InvalidTokenError if not a valid token.
        """
        self.token = token
        self.key_id = self.extract_keyid()
        return self.validate(0).get('sub')

    def extract_keyid(self):
        try:
            headers = get_unverified_header(self.token)
        except PyJWTError as ex:
            raise InvalidTokenHeader(ex)

        if 'kid' not in headers:
            raise InvalidTokenHeader(
                "Token header missing kid property: {}".format(headers))

        return headers['kid']

    def validate(self, retry_ct):
        """
        Return the decoded payload from the token
        Raise InvalidTokenError if not a valid token.
        """
        pubkey = self.get_key(retry_ct == 1)
        if pubkey is None:
            if retry_ct == 0:
                return self.validate(retry_ct + 1)
            raise NoMatchingPublicKey(
                "No public key for token keyID: {}".format(self.key_id))
        try:
            return self.decode_token(pubkey)
        except InvalidSignatureError as ex:
            if retry_ct == 0:
                return self.validate(retry_ct + 1)
            raise InvalidTokenError(ex)
        except PyJWTError as ex:
            raise InvalidTokenError(ex)

    def get_key(self, force_update):
        pub_key_dict = UWIdPToken.JWKS_CLIENT.get_jwks(
            force_update=force_update)
        return pub_key_dict.get(self.key_id)

    def decode_token(self, pubkey):
        return decode(self.token,
                      options=self.JWT_OPTIONS,
                      key=pubkey,
                      algorithms=self.SIGNING_ALGORITHMS,
                      issuer=getattr(settings, 'TOKEN_ISSUER'),
                      audience=getattr(settings, 'TOKEN_AUDIENCE'),
                      leeway=int(getattr(settings, 'TOKEN_LEEWAY', 1)))

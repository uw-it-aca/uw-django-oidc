from django.conf import settings
from jwt import decode
from jwt.exceptions import PyJWTError, InvalidSignatureError
from uw_oidc.exceptions import InvalidTokenError
from uw_oidc.jwks import UW_JWKS


class UWIdPToken(object):
    JWT_OPTIONS = {
        'require_exp': True, 'require_iat': True, 'verify_signature': True,
        'verify_iat': True, 'verify_exp': True, 'verify_iss': True,
        'verify_aud': True,
    }
    SIGNING_ALGORITHMS = [
        'RS256', 'RS384', 'RS512', 'HS256', 'HS384', 'HS512', 'ES256'
    ]
    KEY_URL = '/idp/profile/oidc/keyset'

    def __init__(self, token):
        self.token = token

    def decode_token(self):
        """
        Return the decoded payload from the token, or raise InvalidTokenError
        if not a valid token.
        """
        key = self.get_key()
        try:
            return decode(self.token,
                          options=self.JWT_OPTIONS,
                          key=key,
                          algorithms=self.SIGNING_ALGORITHMS,
                          issuer=getattr(settings, 'TOKEN_ISSUER', 'uwidp'),
                          audience=getattr(settings, 'TOKEN_AUDIENCE', ''),
                          leeway=int(getattr(settings, 'TOKEN_LEEWAY', 1)))

        except InvalidSignatureError as ex:
            if self.get_key(force_update=True) != key:
                return self.decode_token()

            raise InvalidTokenError(ex)

        except PyJWTError as ex:
            raise InvalidTokenError(ex)

    def username_from_token(self):
        self.key_id = self.extract_keyid()
        return self.decode_token().get('sub')

    def extract_keyid(self):
        # TODO
        return "defaultEC"

    def get_key(self, force_update=False):
        return UWIdPToken.JWKS_CLIENT.get_pubkey(
            self.key_id, force_update=force_update)

import logging
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from jwt import decode, get_unverified_header
from jwt.exceptions import PyJWTError, InvalidSignatureError
from uw_oidc.exceptions import (
    InvalidTokenError, InvalidTokenHeader, NoMatchingPublicKey)
from uw_oidc.jwks import UW_JWKS

logger = logging.getLogger(__name__)


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
        if getattr(settings, 'TOKEN_AUDIENCE') is None:
            raise ImproperlyConfigured(
                'You must have TOKEN_AUDIENCE in your project settings')

    def username_from_token(self, token):
        """
        Raise InvalidTokenError if not a valid token.
        """
        self.token = token
        self.key_id, self.alg = self.extract_keyid()
        return self.validate().get('sub')

    def extract_keyid(self):
        try:
            headers = get_unverified_header(self.token)
        except PyJWTError as ex:
            raise InvalidTokenHeader(ex)

        if 'kid' not in headers or 'alg' not in headers:
            logger.error(
                "InvalidTokenHeader: missing properties: {}".format(headers))
            raise InvalidTokenHeader("{}".format(headers))

        return headers['kid'], headers['alg']

    def validate(self, refresh_keys=False):
        """
        Return the decoded payload from the token
        Raise InvalidTokenError if not a valid token.
        """
        pubkey = self.get_key(refresh_keys)
        if pubkey is None:
            if refresh_keys is False:
                return self.validate(refresh_keys=True)
            logger.error("NoMatchingPublicKey for key-id: {}".format(
                self.key_id))
            raise NoMatchingPublicKey(self.key_id)

        try:
            return self.decode_token(pubkey)
        except InvalidSignatureError as ex:
            if refresh_keys is False:
                return self.validate(refresh_keys=True)
            logger.error("{} on token: {}".format(ex, self.token))
            raise InvalidTokenError(ex)
        except PyJWTError as ex:
            logger.error("{} on token {}".format(ex, self.token))
            raise InvalidTokenError(ex)

    def get_key(self, force_update):
        return UWIdPToken.JWKS_CLIENT.get_pubkey(
            self.key_id, self.alg, force_update=force_update)

    def decode_token(self, pubkey):
        return decode(self.token,
                      options=self.JWT_OPTIONS,
                      key=pubkey,
                      algorithms=self.SIGNING_ALGORITHMS,
                      issuer=getattr(settings, 'TOKEN_ISSUER',
                                     "urn:mace:incommon:washington.edu:eval"),
                      audience=getattr(settings, 'TOKEN_AUDIENCE'),
                      leeway=int(getattr(settings, 'TOKEN_LEEWAY', 1)))

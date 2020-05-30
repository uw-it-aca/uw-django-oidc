import logging
from calendar import timegm
from datetime import datetime, timedelta, timezone
from django.conf import settings
from jwt import decode, get_unverified_header
from jwt.exceptions import PyJWTError, InvalidSignatureError
from uw_oidc.exceptions import (
    InvalidTokenError, InvalidTokenHeader, NoMatchingPublicKey)
from uw_oidc.jwks import UW_JWKS
from uw_oidc.logger import log_err

logger = logging.getLogger(__name__)


class UWIdPToken(object):
    JWKS_CLIENT = UW_JWKS()
    JWT_OPTIONS = {
        'require_exp': True, 'require_iat': True, 'verify_signature': True,
        'verify_iat': True, 'verify_exp': True, 'verify_iss': True,
        'verify_aud': True,
    }

    # To avoid algorithm confusion attacks, always specify only
    # the algoriths expected to use for token signature validation.
    SIGNING_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'ES256']

    def username_from_token(self, token):
        """
        Raise InvalidTokenError if not a valid token.
        """
        self.token = token
        self.key_id = self.extract_keyid()
        self.payload = self.get_token_payload()
        return self.payload.get('sub')

    def extract_keyid(self):
        try:
            headers = get_unverified_header(self.token)
        except PyJWTError as ex:
            log_err(logger, {'msg': "InvalidTokenHeader - {}".format(ex),
                             'token': self.token})
            raise InvalidTokenHeader(ex)

        if headers.get('kid') is None or not len(headers['kid']):
            log_err(logger, {'msg': "InvalidTokenHeader - missing kid",
                             'headers': headers})
            raise InvalidTokenHeader()

        return headers['kid']

    def get_token_payload(self, refresh_keys=False):
        """
        Raise InvalidTokenError if not a valid jwt token.
        """
        pubkey = self.get_key(refresh_keys)
        if pubkey is None:
            if refresh_keys is False:
                return self.get_token_payload(refresh_keys=True)
            log_err(logger, {'msg': "NoMatchingPublicKey for the kid",
                             'kid': self.key_id})
            raise NoMatchingPublicKey()

        # When reaching this point, we have got the valid public key.
        try:
            return self.decode_token(pubkey)
        except PyJWTError as ex:
            log_err(logger, {'msg': "InvalidToken - {}".format(ex),
                             'token': self.token})
            raise InvalidTokenError(ex)

    def get_key(self, force_update):
        return UWIdPToken.JWKS_CLIENT.get_pubkey(
            self.key_id, force_update=force_update)

    def decode_token(self, pubkey):
        return decode(
            self.token,
            options=self.JWT_OPTIONS,
            key=pubkey,
            algorithms=self.SIGNING_ALGORITHMS,
            issuer=getattr(settings, 'UW_TOKEN_ISSUER',
                           "https://idp-eval.u.washington.edu"),
            audience=getattr(settings, 'UW_TOKEN_AUDIENCE'),
            leeway=int(getattr(settings, 'UW_TOKEN_LEEWAY', 60)))

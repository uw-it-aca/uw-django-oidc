import logging
from calendar import timegm
from datetime import datetime, timedelta, timezone
from django.conf import settings
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
    # To avoid algorithm confusion attacks, always specify only
    # the algoriths expected to use for token signature validation.
    SIGNING_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'ES256']

    def username_from_token(self, token):
        """
        Raise InvalidTokenError if not a valid token.
        """
        self.token = token
        self.key_id = self.extract_keyid()
        self.payload = self.validate()
        if self.valid_auth_time():
            return self.payload.get('sub')
        raise InvalidTokenError("AuthTimedOut")

    def extract_keyid(self):
        try:
            headers = get_unverified_header(self.token)
        except PyJWTError as ex:
            raise InvalidTokenHeader(ex)

        if headers.get('kid') is None or not len(headers['kid']):
            logger.error("InvalidTokenHeader: missing kid {}".format(headers))
            raise InvalidTokenHeader()

        return headers['kid']

    def validate(self, refresh_keys=False):
        """
        Return the decoded payload from the token
        Raise InvalidTokenError if not a valid token.
        """
        pubkey = self.get_key(refresh_keys)
        if pubkey is None:
            if refresh_keys is False:
                return self.validate(refresh_keys=True)
            logger.error("NoMatchingPublicKey for kid: {}".format(
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
            leeway=int(getattr(settings, 'UW_TOKEN_LEEWAY', 1)))

    def valid_auth_time(self):
        """
        Raise InvalidTokenError if the id-token is not fresh enough
        """
        timeout = int(getattr(settings, 'UW_TOKEN_MAX_AGE', 300))
        age_limit = timegm(datetime.utcnow().utctimetuple()) - timeout
        try:
            return int(self.payload['auth_time']) >= age_limit
        except KeyError as ex:
            pass
        logger.error("Token auth time out: {} issued before {}".format(
            self.payload, age_limit))
        return False

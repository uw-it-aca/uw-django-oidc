from django.conf import settings
from jwt import decode
from jwt.exceptions import PyJWTError, InvalidSignatureError
from uw_oidc.exceptions import InvalidTokenError
from restclients_core.dao import DAO
from restclients_core.exceptions import DataFailureException
from os.path import abspath, dirname
import os
import json


class UWIDP_DAO(DAO):
    def service_name(self):
        return 'uw_idp'

    def service_mock_paths(self):
        return [abspath(os.path.join(dirname(__file__), 'resources'))]

    def delete_cache_key(self, url):
        cache = self.get_cache()
        cache_key = cache._get_key(self.service_name(), url)
        cache.client.delete(cache_key)


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
        return self.decode_token().get('sub')

    def get_key(self, force_update=False):
        dao = UWIDP_DAO()

        if force_update:
            dao.delete_cache_key(self.KEY_URL)

        response = dao.getURL(
            self.KEY_URL, headers={'Accept': 'application/json'})

        if response.status != 200:
            raise DataFailureException(
                self.KEY_URL, response.status, response.data)

        data = json.loads(response.data)
        for key in data.get('keys', []):
            # TODO
            pass

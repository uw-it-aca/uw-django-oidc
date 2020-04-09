import json
import os
import logging
from os.path import abspath, dirname
from jwcrypto.jwk import JWK
from jwcrypto.common import JWException
from restclients_core.dao import DAO
from uw_oidc.exceptions import (
    JwksDataError, JwksFetchError, JwksDataInvalidJson)

logger = logging.getLogger(__name__)


class UWIDP_DAO(DAO):
    URL = '/idp/profile/oidc/keyset'

    def service_name(self):
        return 'uw_idp'

    def service_mock_paths(self):
        return [abspath(os.path.join(dirname(__file__), 'resources'))]

    def delete_cache_key(self):
        cache = self.get_cache()
        cache_key = cache._get_key(self.service_name(), UWIDP_DAO.URL)
        cache.client.delete(cache_key)

    def get_jwks(self, force_update):
        """
        return a dictionary of {kid_value: rsa_public_key}.
        raise InvalidTokenError if access or data failure
        """
        if force_update:
            self.delete_cache_key()
        response = self.getURL(UWIDP_DAO.URL,
                               headers={'Accept': 'application/json'})
        if response.status != 200:
            raise JwksFetchError(json.dumps({'url': UWIDP_DAO.URL,
                                             'Status code': response.status,
                                             'data': response.data}))
        return response.data


class UW_JWKS(object):

    def __init__(self, dao_for_jwks=None):
        self.dao = dao_for_jwks
        if self.dao is None:
            self.dao = UWIDP_DAO()

    def get_pubkey(self, keyid, force_update=False):
        """
        Extract the public key coresponding to the keyid
        """
        resp_data = self.dao.get_jwks(force_update)

        try:
            json_wks = json.loads(resp_data)
        except Exception as ex:
            raise JwksDataInvalidJson("{}: {}".format(resp_data, ex))

        if 'keys' not in json_wks:
            raise JwksDataError(
                "{}: Missing 'keys' attribute".format(json_wks))

        for key in json_wks['keys']:
            try:
                if key.get('kid') == keyid:
                    return JWK(**key).export_to_pem()
            except JWException as ex:
                raise JwksDataError("{}: {}".format(key, ex))
        return None

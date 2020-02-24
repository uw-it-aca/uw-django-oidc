import json
import os
from os.path import abspath, dirname
from jwt.algorithm import RSAAlgorithm
from restclients_core.dao import DAO
from uw_oidc.exceptions import JwksDataError, JwksFetchError


class UWIDP_DAO(DAO):
    def service_name(self):
        return 'uw_idp'

    def service_mock_paths(self):
        return [abspath(os.path.join(dirname(__file__), 'resources'))]

    def delete_cache_key(self, url):
        cache = self.get_cache()
        cache_key = cache._get_key(self.service_name(), url)
        cache.client.delete(cache_key)


class UW_JWKS(object):
    dao = UWIDP_DAO()
    rsaa = RSAAlgorithm(RSAAlgorithm.SHA256)
    JWKS_PATH = '/idp/profile/oidc/keyset'

    def get_jwks(self, force_update=False):
        """
        return a dictionary of {kid_value: rsa_public_key}.
        raise InvalidTokenError if access or data failure
        """
        if force_update:
            self.dao.delete_cache_key(self.JWKS_PATH)

        response = self.dao.getURL(self.JWKS_PATH,
                                   headers={'Accept': 'application/json'})
        if response.status != 200:
            raise JwksFetchError(
                "Error fetching %s.  Status code: %s.  Message: %s.".format(
                    self.JWKS_PATH, response.status, response.data))

        return self.filter_keys(response.data)

    def filter_keys(self, resp_data):
        """
        Extract RSA keys
        """
        try:
            json_wks = json.loads(resp_data)
        except Exception as ex:
            raise JwksDataInvalidJson(ex)

        if 'keys' not in json_wks:
            raise JwksDataError("No 'keys': {}".format(resp_data))

        pub_key_dict = {}
        for key in json_wks['keys']:
            try:
                if ('RSA' == key.get('kty') and "sig" == key.get('use') and
                        len(key.get('kid')) and 'n' in key and 'e' in key):
                    pub_key_dict[key['kid']] = self.rsaa.from_jwk(
                        json.dumps(key))
            except InvalidKeyError as ex:
                raise JwksDataError(ex)
        return pub_key_dict

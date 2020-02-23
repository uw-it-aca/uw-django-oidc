from base64 import urlsafe_b64decode
from binascii import hexlify
import json
import struct
import os
from os.path import abspath, dirname
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from restclients_core.dao import DAO
from uw_oidc.exceptions import (
    JwksFetchError, JwksDataInvalidJson, JwksDataMissingProperty)


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
    JWKS_PATH = '/idp/profile/oidc/keyset'

    def get_jwks(self, force_update=False):
        """
        return a dictionary of {kid_value: rsa_public_key}.
        raise JwksDataFailure if access
        """
        if force_update:
            self.dao.delete_cache_key(self.JWKS_PATH)

        response = self.dao.getURL(self.JWKS_PATH,
                                   headers={'Accept': 'application/json'})
        if response.status != 200:
            raise JwksFetchError(
                "Error fetching %s.  Status code: %s.  Message: %s.".format(
                    self.JWKS_PATH, response.status, response.data))

        return self.get_public_key(response.data)

    def get_public_key(self, resp_data):
        try:
            json_wks = json.loads(resp_data)
        except Exception as ex:
            raise JwksDataInvalidJson(ex)

        if 'keys' not in json_wks:
            raise JwksDataMissingProperty("No 'keys': {}".format(resp_data))

        pub_key_dict = {}
        for key in json_wks['keys']:
            if ('RSA' == key.get('kty') and
                    "sig" == key.get('use') and
                    len(key.get('kid'))):

                # e: the exponent for a standard pem
                # n: the moduluos for a standard pem
                if 'n' not in key or 'e' not in key:
                    raise JwksDataMissingProperty(
                        'Invalid RSA key: {}'.format(key))

                try:
                    rsa_pub = RSAPublicNumbers(decode_int(key['e']),
                                               decode_int(key['n']))
                    pub_key_dict[key['kid']] = rsa_pub.public_key(
                        default_backend())
                except Exception as ex:
                    raise InvalidJwkError('Invalid RSA key: {}'.format(ex))
        return pub_key_dict


def decode_int(val):
    return int(hexlify(base64url_decode(n)), 16)


def base64url_decode(payload):
    size = len(payload) % 4
    if size == 2:
        payload += '=='
    elif size == 3:
        payload += '='
    elif size != 0:
        raise ValueError('Invalid base64 string')
    return urlsafe_b64decode(payload.encode('utf-8'))

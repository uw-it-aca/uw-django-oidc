import json
import os
import logging
from os.path import abspath, dirname
from jwcrypto.jwk import JWK
from jwcrypto.common import JWException
from restclients_core.dao import DAO
from restclients_core.exceptions import DataFailureException
from uw_oidc.exceptions import JwksDataError, JwksFetchError
from uw_oidc.logger import log_err

logger = logging.getLogger(__name__)


class UWIDP_DAO(DAO):
    URL = '/idp/profile/oidc/keyset'

    def service_name(self):
        return 'uwidp'

    def service_mock_paths(self):
        return [abspath(os.path.join(dirname(__file__), 'resources'))]

    def get_jwks(self, force_update):
        """
        return the response data from JWKS
        raise JwksFetchError if the response code is not 200
              or read timeout, max retry error...
        """
        if force_update:
            self.clear_cached_response(UWIDP_DAO.URL)
        try:
            response = self.getURL(UWIDP_DAO.URL,
                                   headers={'Accept': 'application/json'})
        except DataFailureException as ex:
            log_err(logger, {'msg': "JwksFetchError - {}".format(ex),
                             'url': UWIDP_DAO.URL})
            raise JwksFetchError()

        if response.status != 200:
            log_err(logger, {'msg': "JwksFetchError",
                             'url': UWIDP_DAO.URL,
                             'Status code': response.status,
                             'data': response.data})
            raise JwksFetchError()
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
        except json.JSONDecodeError as ex:
            log_err(logger, {'msg': "JwksDataError - {}".format(ex),
                             'data': resp_data})
            raise JwksDataError(ex)

        if 'keys' not in json_wks:
            log_err(logger, {'msg': "JwksDataError - Missing 'keys' attribute",
                             'jwks': json_wks})
            raise JwksDataError("Missing keys attribute")

        for key in json_wks['keys']:
            try:
                if key.get('kid') == keyid:
                    return JWK(**key).export_to_pem()
            except JWException as ex:
                log_err(logger, {'msg': "JwksDataError - {}".format(ex),
                                 'key': key})
                raise JwksDataError(ex)
        return None

from restclients_core.dao import DAO
from os.path import abspath, dirname
import os
import json


class UW_IDP_DAO(DAO):
    def service_name(self):
        return 'uw_idp'

    def service_mock_paths(self):
        return [abspath(os.path.join(dirname(__file__), 'resources'))]


def get_key():
    response = UW_IDP_DAO().getURL('/idp/profile/oidc/keyset',
                                   headers={'Accept': 'application/json'})
    if response.status != 200:
        # Return an empty key on failure
        return ''

    data = json.loads(response.data)
    for key in data.get('keys', []):
        # TODO
        pass
    return ''

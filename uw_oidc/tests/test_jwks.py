from django.test import TestCase
from unittest.mock import patch
from restclients_core.exceptions import DataFailureException
from restclients_core.models import MockHTTP
from uw_oidc.jwks import (
    UWIDP_DAO, UW_JWKS, JwksFetchError, JwksDataError)


class Test_UWIDP_DAO(TestCase):
    def test_get_jwks(self):
        self.assertIsNotNone(UWIDP_DAO().get_jwks(True))

    @patch.object(UWIDP_DAO, 'getURL', spec=True)
    def test_force_update(self, mock):
        response = MockHTTP()
        response.status = 404
        response.reason = "Not Found"
        mock.return_value = response
        self.assertRaises(JwksFetchError, UWIDP_DAO().get_jwks, False)

        mock.side_effect = DataFailureException('', 0, '')
        self.assertRaises(JwksFetchError, UWIDP_DAO().get_jwks, False)


class Test_UW_JWKS(TestCase):
    def setUp(self):
        self.jwks = UW_JWKS()

    def test_get_pubkey(self):
        self.assertIsNotNone(self.jwks.get_pubkey("defaultRSA",
                                                  force_update=True))

    @patch.object(UWIDP_DAO, 'get_jwks', spec=True)
    def test_no_matching_key(self, mock):
        # no matching key
        mock.return_value = (
            '{"keys":[{"kty":"EC","kid":"defaultEC",'
            '"x":"rih4qpHil8F2G-VW8X","y":"IgB-KnnoORMTZrK7wIw"}]}')
        self.assertIsNone(self.jwks.get_pubkey("defaultRSA"))

        # bad json
        mock.return_value = '{"keys":[]'
        self.assertRaises(JwksDataError, self.jwks.get_pubkey,
                          "defaultRSA")

        # bad data
        mock.return_value = '{"keys":[{"kid":"defaultRSA", "kty":"RSA"}]}'
        self.assertRaises(JwksDataError, self.jwks.get_pubkey,
                          "defaultRSA")

        mock.return_value = '{}'
        self.assertRaises(JwksDataError, self.jwks.get_pubkey, "defaultRSA")

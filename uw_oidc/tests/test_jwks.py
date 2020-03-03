from django.test import TestCase
from unittest.mock import patch
from uw_oidc.jwks import (
    UWIDP_DAO, UW_JWKS, JwksFetchError, JwksDataError, JwksDataInvalidJson)


class Test_UWIDP_DAO(TestCase):
    def test_get_jwks(self):
        self.assertIsNotNone(UWIDP_DAO().get_jwks)


class Test_UW_JWKS(TestCase):
    def setUp(self):
        self.jwks = UW_JWKS()

    def test_get_pubkey(self):
        self.assertIsNotNone(self.jwks.get_pubkey("defaultRSA"))

    @patch.object(UWIDP_DAO, 'get_jwks', spec=True)
    def test_no_matching_key(self, mock):
        # no matching key
        mock.return_value = (
            '{"keys":[{"kty":"EC","use":"sig","crv":"P-256","kid":"defaultEC",'
            '"x":"rih4qpHil8F2G-VW8XHysQvA9bYma6maiVKqRBpfLIk",'
            '"y":"IgB-KnnoORMTZrK7wIwXQ5B3JL5FpaLZqHAlGEmnQPQ"}]}')
        self.assertIsNone(self.jwks.get_pubkey("defaultRSA"))

        # bad json
        mock.return_value = '{"keys":[]'
        self.assertRaises(JwksDataInvalidJson, self.jwks.get_pubkey,
                          "defaultRSA")

        # bad data
        mock.return_value = '{"keys":[{"kid":"defaultRSA", "kty":"RSA"}]}'
        self.assertRaises(JwksDataError, self.jwks.get_pubkey,
                          "defaultRSA")

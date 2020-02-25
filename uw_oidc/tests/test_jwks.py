from django.test import TestCase
from unittest.mock import patch
from uw_oidc.jwks import (
    UWIDP_DAO, UW_JWKS, JwksFetchError, JwksDataError, JwksDataInvalidJson)


class Test_UWIDP_DAO(TestCase):
    def test_get_jwks(self):
        self.assertRaises(JwksFetchError, UWIDP_DAO().get_jwks, False)


class Test_UW_JWKS(TestCase):
    def setUp(self):
        self.jwks = UW_JWKS()

    @patch.object(UWIDP_DAO, 'get_jwks', spec=True)
    def test_get_pubkey(self, mock):
        # has key
        mock.return_value = (
            '{"keys":[{"kty":"RSA","e":"AQAB","use":"sig","kid":"defaultRSA",'
            '"n":"kM0fI-f75oCeGBmk9xW_kESLjQBv4i-f1HPtHp33auQaVbmPrwo'
            'I6RRnRq0wfMJCHVAPDsF31nPEJLSQSm4fO2ekgq8EoJfBYEQmtQ'
            'UvpFrdLu_ZqsrMcLxaA3-fuoO2PJcl62Tr_uRBEaU7bU0DFvckY'
            '03ErehzhHPVRDy9IbE-bQafq_f03ehT8FIaMasmOs7BZDHTDb2F'
            '655lOUyd6XzkI7_NGhU2VZADaYl41ctMnH_6Cfu4V-RAw-4-jPm'
            'PHhoXYkYvFSWMJAQUEAfJCLEHUFOfeNnDpJ_ugb6a-z8MiboKur'
            'ca3kGH4CsITNoVPzMx-2ic0Ayo4hg1ci9RHQ"}]}')
        self.assertIsNotNone(self.jwks.get_pubkey("defaultRSA"))

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

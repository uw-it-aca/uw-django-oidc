from calendar import timegm
from datetime import datetime
from datetime import datetime, timedelta, timezone
from django.test import TestCase, override_settings
from unittest.mock import patch
from jwt.exceptions import ExpiredSignatureError
from uw_oidc.id_token import (
    UWIdPToken, InvalidTokenHeader, NoMatchingPublicKey, InvalidSignatureError,
    PyJWTError, InvalidTokenError)


@override_settings(UW_TOKEN_AUDIENCE='my',
                   UW_TOKEN_LEEWAY=3,
                   UW_TOKEN_ISSUER='https://idp-eval.u.washington.edu')
class TestIdToken(TestCase):
    bad_token = (
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1d2lkcCIsImlhdCI'
        '6MTU4MjE0NjA3MSwiZXhwIjozMzE3NzQ5MjcxLCJhdWQiOiJteXV3Iiwic3ViIjo'
        'iamF2ZXJhZ2UiLCJHaXZlbl9uYW1lIjoiSiIsIkZhbWlseV9uYW1lIjoiQXZlcmF'
        'nZSIsIkVtYWlsIjoiamF2ZXJhZ2VAdXcuZWR1IiwiU2NvcGVkX2FmZmlsaWF0aW9'
        'uIjoiZW1wbG95ZWUgbWVtYmVyIn0.NRlQDOWMofVPZJ5mwN5Jk_KqbV4KRAMO7rp'
        'M-rbs1tU')
    id_token = (
        'eyJraWQiOiJkZWZhdWx0UlNBIiwiYWxnIjoiUlMyNTYifQ.eyJhdF9oYXNoIjoie'
        'mdIM2hWS0NnQU1LLS1EQWtYYi1nQSIsInN1YiI6InV3Y2RlbW8iLCJhdWQiOiJva'
        'WRjXC9teXV3IiwiYWNyIjoicGFzc3dvcmQiLCJhdXRoX3RpbWUiOjE1ODMxNzM2O'
        'DAsImlzcyI6Imh0dHBzOlwvXC9pZHAtZXZhbC51Lndhc2hpbmd0b24uZWR1IiwiZ'
        'XhwIjoxNTgzMTc3MjgxLCJpYXQiOjE1ODMxNzM2ODEsIm5vbmNlIjoiS2xuRnhwN'
        '2JPd18wMmtubUdTblVLeC1vVE81ZnhwMEtTa2FjMk13Z05ocyJ9.T8YSGyP7Ltlz'
        'bfRcWj4xs8Izeps7zyhDX12jxYGDemY3KO0v5iSs0uAHhLddq5uS1SG53iEkMdpc'
        'XeOI6kecdye6tdGdKDpUEbbxmpPP5VXp2eUk77YonDfWylICvWs6DKyDqE03yfop'
        'KBLrBFN2hGk9P5ZrtvB0ZdYSd6DFgeTucNX03-g6q-q70o8o9ZDr1rz98BLdBtyA'
        'Otwl9IJh53IioFD4U6zvS5HWjOr-7RivbwO0_BhIXS7Uo8WACYMF6Z6VzAqfrHKi'
        'xXwpvVDNyZYV2R_KqwwPVgoeT5PMM_y-xidMMDtNlGCRDDUo0xrliuaOYrnAOzVT'
        'SDgB5cFi4Q')

    def setUp(self):
        self.decoder = UWIdPToken()
        self.decoder.token = self.id_token

    def test_extract_keyid(self):
        self.assertEqual(self.decoder.extract_keyid(), 'defaultRSA')

        # error parsing header
        with patch('uw_oidc.id_token.get_unverified_header') as mock:
            mock.return_value = {}
            self.assertRaises(InvalidTokenHeader, self.decoder.extract_keyid)

            mock.side_effect = PyJWTError
            self.assertRaises(InvalidTokenHeader, self.decoder.extract_keyid)

    def test_decode_token(self):
        self.decoder.key_id = self.decoder.extract_keyid()
        # the closest to a valid token
        self.assertRaises(ExpiredSignatureError,
                          self.decoder.decode_token,
                          self.decoder.get_key(False))

    def test_get_token_payload(self):
        self.decoder.key_id = self.decoder.extract_keyid()

        # expired token
        try:
            result = self.decoder.get_token_payload()
        except Exception as ex:
            self.assertEqual(str(ex),
                             "InvalidTokenError: Signature has expired")

        # token using invalid algorithm
        self.decoder.token = self.bad_token
        self.assertRaises(InvalidTokenError, self.decoder.get_token_payload)

        # no matching public key
        with patch.object(UWIdPToken, 'get_key', return_value=None) as mock2:
            self.assertRaises(NoMatchingPublicKey,
                              self.decoder.get_token_payload)
            self.assertEqual(mock2.call_count, 2)

    @patch.object(UWIdPToken, 'decode_token')
    def test_username_from_token(self, mock_decode_token):
        mock_decode_token.return_value = {'sub': 'javerage'}
        self.assertEqual(self.decoder.username_from_token(self.id_token),
                         'javerage')

        mock_decode_token.return_value = {}
        self.assertIsNone(self.decoder.username_from_token(self.id_token))

from django.test import TestCase, override_settings
from unittest.mock import patch
from jwt.exceptions import ExpiredSignatureError
from uw_oidc.id_token import (
    UWIdPToken, InvalidTokenHeader, NoMatchingPublicKey,
    PyJWTError, InvalidTokenError)


@override_settings(TOKEN_AUDIENCE='myuw', TOKEN_LEEWAY=3, TOKEN_ISSUER='uwidp')
class TestIdToken(TestCase):
    KEY = 'test1234test1234test1234test1234'
    valid_token = (
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1d2lkcCIsImlhdCI'
        '6MTU4MjE0NjA3MSwiZXhwIjozMzE3NzQ5MjcxLCJhdWQiOiJteXV3Iiwic3ViIjo'
        'iamF2ZXJhZ2UiLCJHaXZlbl9uYW1lIjoiSiIsIkZhbWlseV9uYW1lIjoiQXZlcmF'
        'nZSIsIkVtYWlsIjoiamF2ZXJhZ2VAdXcuZWR1IiwiU2NvcGVkX2FmZmlsaWF0aW9'
        'uIjoiZW1wbG95ZWUgbWVtYmVyIn0.NRlQDOWMofVPZJ5mwN5Jk_KqbV4KRAMO7rp'
        'M-rbs1tU')
    expired_token = (
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1d2lkcCIsImlhdCI'
        '6MTU4MjE0NjA3MSwiZXhwIjoxNTgyMTQ2MDcxLCJhdWQiOiJteXV3Iiwic3ViIjo'
        'iamF2ZXJhZ2UiLCJHaXZlbl9uYW1lIjoiSiIsIkZhbWlseV9uYW1lIjoiQXZlcmF'
        'nZSIsIkVtYWlsIjoiamF2ZXJhZ2VAdXcuZWR1IiwiU2NvcGVkX2FmZmlsaWF0aW9'
        'uIjoiZW1wbG95ZWUgbWVtYmVyIn0.EJjWjawYeKhUCKncaR0WQneS3WUcY_lSH5M'
        'O288DEyI')

    def setUp(self):
        self.decoder = UWIdPToken()

    @patch('uw_oidc.id_token.decode', spec=True)
    def test_decode_token_call(self, mock_decode):
        self.decoder.token = 'abc'
        result = self.decoder.decode_token(self.KEY)
        mock_decode.assert_called_once_with(
            'abc', options=UWIdPToken.JWT_OPTIONS,
            algorithms=UWIdPToken.SIGNING_ALGORITHMS, key=self.KEY,
            audience='myuw', issuer='uwidp', leeway=3)

    def test_decode_token(self):
        # valid token
        self.decoder.token = self.valid_token
        self.assertEqual(
            self.decoder.decode_token(self.KEY),
            {'iss': 'uwidp',
             'aud': 'myuw',
             'sub': 'javerage',
             'Given_name': 'J',
             'Family_name': 'Average',
             'iat': 1582146071,
             'exp': 3317749271,
             'Email': 'javerage@uw.edu',
             'Scoped_affiliation': 'employee member'})

        # expired token
        self.decoder.token = self.expired_token
        self.assertRaises(ExpiredSignatureError,
                          self.decoder.decode_token, self.KEY)

    @patch('uw_oidc.id_token.get_unverified_header', spec=True)
    def test_extract_keyid(self, mock_get_unverified_header):
        self.decoder.token = self.valid_token

        # header with right arrtibutes
        mock_get_unverified_header.return_value = {'kid': 'sdxywn',
                                                   "alg": "RS256",
                                                   "typ": "JWT"}
        key = self.decoder.extract_keyid()
        self.assertEqual(key, 'sdxywn')

        # header without key id
        mock_get_unverified_header.return_value = {"alg": "RS256",
                                                   "typ": "JWT"}
        self.assertRaises(InvalidTokenHeader, self.decoder.extract_keyid)

        # error parsing header
        mock_get_unverified_header.side_effect = PyJWTError
        self.decoder.token = self.valid_token
        self.assertRaises(InvalidTokenHeader, self.decoder.extract_keyid)

    @patch.object(UWIdPToken.JWKS_CLIENT, 'get_pubkey', return_value='a')
    def test_get_key(self, mock_get_pubkey):
        self.decoder.key_id = 'sdxywn'
        self.assertEqual(self.decoder.get_key(False), 'a')

    @patch.object(UWIdPToken.JWKS_CLIENT, 'get_pubkey', spec=True)
    def test_validate(self, mock_get_pubkey):
        self.decoder.token = self.valid_token
        self.decoder.key_id = 'sdxywn'

        # successful
        mock_get_pubkey.return_value = self.KEY
        result = self.decoder.validate()
        self.assertTrue('sub' in result)
        self.assertEqual(mock_get_pubkey.call_count, 1)

        # no public key
        mock_get_pubkey.return_value = None
        self.assertRaises(NoMatchingPublicKey, self.decoder.validate)
        self.assertEqual(mock_get_pubkey.call_count, 3)

        # Failed to validate signature
        mock_get_pubkey.return_value = 'b'
        self.assertRaises(InvalidTokenError, self.decoder.validate)
        self.assertEqual(mock_get_pubkey.call_count, 5)

        # Failed to validate token
        self.decoder.token = 'abc'
        mock_get_pubkey.return_value = self.KEY
        self.assertRaises(InvalidTokenError, self.decoder.validate)
        self.assertEqual(mock_get_pubkey.call_count, 6)

    @patch.object(UWIdPToken, 'extract_keyid', return_value='sdxywn')
    @patch.object(UWIdPToken, 'get_key')
    @patch.object(UWIdPToken, 'decode_token', return_value={'sub': 'javerage'})
    def test_username_from_token(self, mock_extract_keyid, mock_get_key,
                                 mock_decode_token):
        mock_get_key.return_value = self.KEY
        self.assertEqual(self.decoder.username_from_token(self.valid_token),
                         'javerage')

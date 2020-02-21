from django.test import TestCase, override_settings
from unittest.mock import patch
from uw_oidc.id_token import UWIdPToken


@override_settings(TOKEN_AUDIENCE='myuw', TOKEN_LEEWAY=3)
class TestIdToken(TestCase):
    KEY = 'test1234test1234test1234test1234'

    def setUp(self):
        self.valid_token = (
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1d2lkcCIsImlhdCI'
            '6MTU4MjE0NjA3MSwiZXhwIjozMzE3NzQ5MjcxLCJhdWQiOiJteXV3Iiwic3ViIjo'
            'iamF2ZXJhZ2UiLCJHaXZlbl9uYW1lIjoiSiIsIkZhbWlseV9uYW1lIjoiQXZlcmF'
            'nZSIsIkVtYWlsIjoiamF2ZXJhZ2VAdXcuZWR1IiwiU2NvcGVkX2FmZmlsaWF0aW9'
            'uIjoiZW1wbG95ZWUgbWVtYmVyIn0.NRlQDOWMofVPZJ5mwN5Jk_KqbV4KRAMO7rp'
            'M-rbs1tU')

    @patch('uw_oidc.id_token.decode', spec=True)
    @patch.object(UWIdPToken, 'get_key', return_value=KEY)
    def test_decode_token_call(self, mock_get_key, mock_decode):
        result = UWIdPToken('abc').decode_token()
        mock_decode.assert_called_once_with(
            'abc', options=UWIdPToken.JWT_OPTIONS,
            algorithms=UWIdPToken.SIGNING_ALGORITHMS, key=self.KEY,
            audience='myuw', issuer='uwidp', leeway=3)

    @patch.object(UWIdPToken, 'get_key', return_value=KEY)
    def test_decode_token_valid(self, mock_get_key):
        self.assertEqual(UWIdPToken(self.valid_token).decode_token(), {
            'iss': 'uwidp',
            'aud': 'myuw',
            'sub': 'javerage',
            'Given_name': 'J',
            'Family_name': 'Average',
            'iat': 1582146071,
            'exp': 3317749271,
            'Email': 'javerage@uw.edu',
            'Scoped_affiliation': 'employee member'})

    @patch.object(UWIdPToken, 'get_key', return_value=KEY)
    def test_username_from_token(self, mock_get_key):
        self.assertEqual(UWIdPToken(self.valid_token).username_from_token(),
                         'javerage')

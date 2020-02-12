from django.test import TestCase, override_settings
from uw_oidc.id_token import get_payload_from_token
import mock


@override_settings(TOKEN_ISSUER='uwidp', TOKEN_AUDIENCE='myuw', TOKEN_LEEWAY=3)
class TestIdToken(TestCase):
    @mock.patch('uw_oidc.id_token.decode')
    def test_get_payload_from_token(self, mock_decode):
        result = get_payload_from_token('abc')
        mock_decode.assert_called_with('abc', options={
                'require_exp': True, 'require_iat': True, 'require_nbf': True,
                'verify_signature': True, 'verify_iat': True,
                'verify_nbf': True, 'verify_exp': True, 'verify_iss': True,
                'verify_aud': True},
                audience='myuw', issuer='uwidp', leeway=3)

from django.test import TestCase
from django.conf import settings
from uw_oidc.session_util import (
    create_session_user, get_token_from_session,
    set_token_in_session, is_valid_userid)


class TestSessionUser(TestCase):
    def test_create_session_user(self):
        with self.settings(SESSION_TOKEN_NAME='idtoken'):
            pass

    def test_set_token_in_session(self):
        with self.settings(SESSION_TOKEN_NAME='idtoken'):
            pass

    def test_set_token_in_session(self):
        with self.settings(SESSION_TOKEN_NAME='idtoken'):
            pass

    def test_is_valid_userid(self):
        pass

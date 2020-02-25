"""
Custom exceptions for uw_oidc
"""


class InvalidTokenError(Exception):
    pass


class InvalidTokenHeader(InvalidTokenError):
    pass


class NoMatchingPublicKey(InvalidTokenError):
    pass


class JwksFetchError(InvalidTokenError):
    pass


class JwksDataError(InvalidTokenError):
    pass


class JwksDataInvalidJson(JwksDataError):
    pass

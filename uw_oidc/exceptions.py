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


class JwksDataInvalidJson(InvalidTokenError):
    pass


class JwksDataMissingProperty(InvalidTokenError):
    pass

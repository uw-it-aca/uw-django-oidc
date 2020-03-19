"""
Custom exceptions for uw_oidc
"""


class InvalidTokenError(Exception):
    pass


class JwksFetchError(InvalidTokenError):
    pass


class JwksDataError(InvalidTokenError):
    pass


class JwksDataInvalidJson(JwksDataError):
    pass

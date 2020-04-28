"""
Custom exceptions for uw_oidc
"""


class InvalidTokenError(Exception):
    pass

    def __str__(self):
        return "{}: {}".format(self.__class__.__name__,
                               super().__str__())


class JwksFetchError(InvalidTokenError):
    pass


class JwksDataError(InvalidTokenError):
    pass


class JwksDataInvalidJson(JwksDataError):
    pass


class InvalidTokenHeader(InvalidTokenError):
    pass


class NoMatchingPublicKey(InvalidTokenError):
    pass

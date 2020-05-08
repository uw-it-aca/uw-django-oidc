"""
Custom exceptions for uw_oidc.
All of them are returned with the HTTP response code 401.

If it is a Jwks related exception, check Jwks the site.
Otherwise the error is caused by the ID token.
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


class InvalidTokenHeader(InvalidTokenError):
    pass


class NoMatchingPublicKey(InvalidTokenError):
    pass

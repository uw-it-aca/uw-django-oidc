from jwt.exceptions import PyJWTError


class ValidationError(Exception):
    """
    Base class for all exceptions
    """
    pass


class MissingTokenError(ValidationError):
    pass


class InvalidUserError(ValidationError):
    pass


class UserMismatchError(ValidationError):
    pass

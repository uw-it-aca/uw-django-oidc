from django.conf import settings


def get_session_token_name():
    return getattr(settings, "SESSION_TOKEN_NAME", "")


def get_token_audience():
    return getattr(settings, "TOKEN_AUDIENCE", "")


def get_token_issuer():
    return getattr(settings, "TOKEN_ISSUER", "")


def get_token_leeway():
    v = getattr(settings, "TOKEN_LEEWAY", None)
    return int(v) if v else 1

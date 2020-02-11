[![Build Status](https://api.travis-ci.org/uw-it-aca/django-oidc.svg?branch=master)](https://travis-ci.org/uw-it-aca/django-oidc)
[![Coverage Status](https://coveralls.io/repos/uw-it-aca/django-oidc/badge.png?branch=master)](https://coveralls.io/r/uw-it-aca/django-oidc?branch=master)


# django-oidc
A middleware that handles Django request with UW OIDC id-token

To use this - add this to your setting.py's INSTALLED_APPS:

    'uw_oidc',

And this to your MIDDLEWARE_CLASSES:

    'uw_oidc.middleware.IdtokenValidationMiddleware'

To use this client, you'll need these settings in your application or script:

    # a custom http header indicating if the request is from an oidc client
    UWOIDC_CLIENT_HEADER

    # Specifies the name of the token to be stored in Django session
    SESSION_TOKEN_NAME

    # Specifies the required issuer (IdP) of the OIDC token
    TOKEN_ISSUER

    # Specifies the required client (Id) that the OIDC token is issued to
    TOKEN_AUDIENCE

    # Specifies the allowed validity window to accommodate clock skew
    # between the given issue time and expiration time (in minutes)
    # that the ID token is within
    TOKEN_LEEWAY


To make this a dependency for your app, add this to your requirements.txt:

    django-oidc

To install, just run:

    pip install django-oidc

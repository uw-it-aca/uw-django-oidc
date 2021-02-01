# uw-django-oidc

[![Build Status](https://github.com/uw-it-aca/uw-django-oidc/workflows/tests/badge.svg?branch=master)](https://github.com/uw-it-aca/uw-django-oidc/actions)
[![Coverage Status](https://coveralls.io/repos/github/uw-it-aca/uw-django-oidc/badge.svg?branch=master)](https://coveralls.io/github/uw-it-aca/uw-django-oidc?branch=master)
[![PyPi Version](https://img.shields.io/pypi/v/uw-django-oidc.svg)](https://pypi.python.org/pypi/uw-django-oidc)
![Python versions](https://img.shields.io/pypi/pyversions/uw-django-oidc.svg)


A middleware class that authenticates a Django request containing a UW OIDC id-token

### Required settings

```
MIDDLEWARE = ['uw_oidc.middleware.IDTokenAuthenticationMiddleware',]

# Specifies whether requests should use live or mocked resources
RESTCLIENTS_UWIDP_DAO_CLASS='Live'

# UW IDP Web Service hostname
RESTCLIENTS_UWIDP_HOST

# Customizable parameters for urllib3
RESTCLIENTS_UWIDP_TIMEOUT
RESTCLIENTS_UWIDP_POOL_SIZE

# Specifies the required issuer (IdP) of the OIDC token
UW_TOKEN_ISSUER = ''

# Specifies the required client (Id) that the OIDC token is issued to
UW_TOKEN_AUDIENCE = ''

# Specifies the allowed validity window to accommodate clock skew
# between the given expiration time of the ID token (default 60 seconds)
UW_TOKEN_LEEWAY = seconds

# To turn on logging of session authentication and errors
UW_OIDC_ENABLE_LOGGING = True

# Set token based session ago (default 8 hours)
UW_TOKEN_SESSION_AGE = seconds
```

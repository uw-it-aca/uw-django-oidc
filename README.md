# uw-django-oidc

[![Build Status](https://api.travis-ci.com/uw-it-aca/uw-django-oidc.svg?branch=master)](https://travis-ci.com/uw-it-aca/uw-django-oidc)
[![Coverage Status](https://coveralls.io/repos/github/uw-it-aca/uw-django-oidc/badge.svg?branch=master)](https://coveralls.io/github/uw-it-aca/uw-django-oidc?branch=master)
[![PyPi Version](https://img.shields.io/pypi/v/uw-django-oidc.svg)](https://pypi.python.org/pypi/uw-django-oidc)
![Python versions](https://img.shields.io/pypi/pyversions/uw-django-oidc.svg)


A middleware class that authenticates a Django request containing a UW OIDC id-token

### Settings

```
MIDDLEWARE = ['IDTokenAuthenticationMiddleware',]

# Specifies the required issuer (IdP) of the OIDC token
UW_TOKEN_ISSUER = string (required)

# Specifies the required client (Id) that the OIDC token is issued to
UW_TOKEN_AUDIENCE = string (required)

# Specifies the allowed validity window to accommodate clock skew
# between the given issue time and expiration time (in minutes)
# that the ID token is within
UW_TOKEN_LEEWAY = number of seconds (optional)

# Specifies the max time between user login and
# when the first request reaches the server
UW_TOKEN_MAX_AGE = number of seconds (optional)
```

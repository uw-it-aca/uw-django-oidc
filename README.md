# django-oidc

[![Build Status](https://api.travis-ci.org/uw-it-aca/uw-oidc.svg?branch=master)](https://travis-ci.org/uw-it-aca/uw-oidc)
[![Coverage Status](https://coveralls.io/repos/github/uw-it-aca/uw-oidc/badge.svg?branch=master)](https://coveralls.io/github/uw-it-aca/uw-oidc?branch=master)
[![PyPi Version](https://img.shields.io/pypi/v/uw-oidc.svg)](https://pypi.python.org/pypi/uw-oidc)
![Python versions](https://img.shields.io/pypi/pyversions/uw-oidc.svg)


A middleware class that authenticates a Django request containing a UW OIDC id-token

### Required settings

```
MIDDLEWARE = ['IDTokenAuthenticationMiddleware',]

# Specifies the required issuer (IdP) of the OIDC token
TOKEN_ISSUER = ''

# Specifies the required client (Id) that the OIDC token is issued to
TOKEN_AUDIENCE = ''

# Specifies the allowed validity window to accommodate clock skew
# between the given issue time and expiration time (in minutes)
# that the ID token is within
TOKEN_LEEWAY = ''
```

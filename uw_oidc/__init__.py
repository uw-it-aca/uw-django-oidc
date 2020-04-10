from django.conf import settings


enable_logging = getattr(settings, 'UW_OIDC_ENABLE_LOGGING', None)

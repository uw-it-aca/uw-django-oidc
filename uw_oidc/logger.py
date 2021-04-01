# Copyright 2021 UW-IT, University of Washington
# SPDX-License-Identifier: Apache-2.0

from django.conf import settings

enable_logging = getattr(settings, 'UW_OIDC_ENABLE_LOGGING', None)


def log_err(logger, msg):
    if enable_logging:
        logger.error(msg)


def log_info(logger, msg):
    if enable_logging:
        logger.info(msg)

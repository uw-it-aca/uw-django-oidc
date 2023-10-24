# Copyright 2023 UW-IT, University of Washington
# SPDX-License-Identifier: Apache-2.0

from __future__ import unicode_literals
from django.apps import AppConfig
from restclients_core.dao import MockDAO
import os


from django.apps import AppConfig


class BridgeProvisionerConfig(AppConfig):
    name = 'uw_oidc'
    verbose_name = 'IDTokenAuthenticationMiddleware'

    def ready(self):
        mocks = os.path.join(os.path.dirname(__file__), "resources")
        MockDAO.register_mock_path(mocks)

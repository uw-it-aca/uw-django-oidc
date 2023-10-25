# Copyright 2023 UW-IT, University of Washington
# SPDX-License-Identifier: Apache-2.0

import os
from setuptools import setup

README = """
See the README on `GitHub <https://github.com/uw-it-aca/uw-django-oidc>`_.
"""

version_path = 'uw_oidc/VERSION'
VERSION = open(os.path.join(os.path.dirname(__file__), version_path)).read()
VERSION = VERSION.replace("\n", "")

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

url = "https://github.com/uw-it-aca/uw-django-oidc"
setup(
    name='Uw-Django-Oidc',
    version=VERSION,
    packages=['uw_oidc'],
    author="UW-IT AXDD",
    author_email="aca-it@uw.edu",
    include_package_data=True,
    install_requires=[
        'Django~=4.2',
        'UW-RestClients-Core',
        'pyjwt',
        'jwcrypto'
    ],
    license='Apache License, Version 2.0',
    description=('Midlleware handles Django request with UW OIDC id-token.'),
    long_description=README,
    url=url,
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.8',
    ],
)

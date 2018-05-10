# Copyright 2018 ARICENT HOLDINGS LUXEMBOURG SARL and Cable Television
# Laboratories, Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

__author__ = 'spisarski'

try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup

config = {
    'description': 'Installs OS via IPMI and PXE',
    'author': 'Steve Pisarski',
    'url': 'https://github.com/cablelabs/snaps-kubernetes',
    'download_url': 'https://github.com/cablelabs/snaps-kubernetes.git',
    'author_email': 's.pisarski@cablelabs.com',
    'version': '1.0',
    'packages': find_packages(),
    'install_requires': ['ansible<2.4,>=2.1.0',
                         'mock',
                         'netaddr',
                         'pathlib',
                         'six'],
    'scripts': [],
    'name': 'snaps-kubernetes'
}

setup(**config)

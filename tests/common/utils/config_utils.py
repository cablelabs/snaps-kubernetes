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
import unittest

import pkg_resources
from snaps_common.file import file_utils

from snaps_k8s.common.consts import consts
from snaps_k8s.common.utils import config_utils


class ConfigUtilsTests(unittest.TestCase):
    """
    Tests for snaps_k8s.provision.kubernetes.plugin.k8_impl.k8_utils.py
    """
    def setUp(self):
        config_file = pkg_resources.resource_filename(
            'tests.conf', 'deployment.yaml')
        self.config = file_utils.read_yaml(config_file)

    def test_get_proxy_data(self):
        proxy_data = config_utils.get_proxy_dict(self.config)
        expected = self.config[consts.K8S_KEY][consts.PROXIES_KEY]
        self.assertEqual(expected, proxy_data)
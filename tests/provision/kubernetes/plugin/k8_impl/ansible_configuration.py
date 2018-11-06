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
import logging
import unittest

import pkg_resources
from mock import patch

from snaps_common.file import file_utils
from snaps_k8s.provision import k8_utils

logging.basicConfig(level=logging.DEBUG)


class K8UtilsTests(unittest.TestCase):
    """
    Tests for snaps_k8s.provision.kubernetes.plugin.k8_impl.k8_utils.py
    """

    def setUp(self):
        config_file = pkg_resources.resource_filename(
            'tests.conf', 'deployment.yaml')
        self.config = file_utils.read_yaml(config_file)

    @patch('os.makedirs')
    @patch('snaps_common.ansible_snaps.ansible_utils.apply_playbook')
    @patch('subprocess.call')
    @patch('snaps_k8s.ansible_p.ansible_utils.ansible_configuration.'
           'get_host_master_name', return_value='master')
    def test_install(self, m1, m2, m3, m4):
        """
        Initial test to ensure main code path does not have any syntax or
        import errors
        :return:
        """
        k8_utils.execute(self.config)

    @patch('os.makedirs')
    @patch('snaps_common.ansible_snaps.ansible_utils.apply_playbook')
    @patch('subprocess.call')
    @patch('snaps_k8s.ansible_p.ansible_utils.ansible_configuration.'
           'get_host_master_name', return_value='master')
    def test_clean(self, m1, m2, m3, m4):
        """
        Initial test to ensure main code path does not have any syntax or
        import errors
        :return:
        """
        k8_utils.clean_k8(self.config)

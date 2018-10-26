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

from snaps_k8s.common.utils import file_utils
from snaps_k8s.provision import k8_utils

logging.basicConfig(level=logging.DEBUG)


class K8UtilsTests(unittest.TestCase):
    """
    Tests for snaps_k8s.provision.kubernetes.plugin.k8_impl.k8_utils.py
    """

    def setUp(self):
        self.config_file = pkg_resources.resource_filename(
            'tests.conf', 'deployment.yaml')
        self.config = file_utils.read_yaml(self.config_file)

    @patch('time.sleep')
    @patch('os.makedirs')
    @patch('snaps_k8s.ansible_p.ansible_utils.ansible_playbook_launcher.'
           'execute_system_command', return_value=True)
    @patch('snaps_k8s.ansible_p.ansible_utils.ansible_playbook_launcher.'
           'execute_system_cmd_subprocess', return_value=True)
    @patch('snaps_common.ansible_snaps.ansible_utils.apply_playbook')
    @patch('subprocess.call')
    @patch('snaps_k8s.provision.kubernetes.plugin.k8_impl.k8_utils.'
           '__add_ansible_hosts')
    @patch('snaps_k8s.provision.kubernetes.plugin.k8_impl.k8_utils.'
           '__create_backup_deploy_conf')
    @patch('snaps_k8s.ansible_p.ansible_utils.ansible_configuration.'
           'get_host_master_name', return_value='master')
    def test_provision_preparation(
            self, m1, m2, m3, m4, m5, m6, m7, m8, m9):
        """
        Initial test to ensure main code path does not have any syntax or
        import errors
        :return:
        """
        self.assertIsNotNone(m1)
        self.assertIsNotNone(m2)
        self.assertIsNotNone(m3)
        self.assertIsNotNone(m4)
        self.assertIsNotNone(m5)
        self.assertIsNotNone(m6)
        self.assertIsNotNone(m7)
        self.assertIsNotNone(m8)
        self.assertIsNotNone(m9)
        k8_utils.execute(self.config, self.config_file)

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
import pkg_resources
from snaps import file_utils
from mock import patch
import os
import unittest

from snaps_adrenaline.deployment import config_utils
from snaps_adrenaline.deployment.kubernetes import deployer

TMP_KEY_FILE = '/tmp/foo'

with open(TMP_KEY_FILE, 'wb') as key_file:
    key_file.write('foo')
    key_file.close()


class DeployTests(unittest.TestCase):

    def setUp(self):
        with open(TMP_KEY_FILE, 'wb') as tmp_file:
            tmp_file.write('foo')
            tmp_file.close()

    def tearDown(self):
        os.remove(key_file.name)

    @patch('snaps_common.ansible_snaps.ansible_utils.apply_playbook')
    def test_deploy(self, apply_pb):
        self.assertIsNotNone(apply_pb)
        boot_conf_filename = pkg_resources.resource_filename(
            'tests.deployment.boot.conf', 'boot.yaml')
        boot_conf = file_utils.read_yaml(boot_conf_filename)

        adrenaline_conf_file = pkg_resources.resource_filename(
            'tests.deployment.kubernetes.conf', 'k8s.yaml')
        hb_conf = file_utils.read_yaml(adrenaline_conf_file)
        k8s_conf = config_utils.k8s_conf_dict(boot_conf, hb_conf)

        user = hb_conf['node_info']['user']

        deployer.deploy(k8s_conf, user)

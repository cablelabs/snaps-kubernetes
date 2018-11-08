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
import os
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

    def test_get_artifact_dir(self):
        artifact_dir = config_utils.get_artifact_dir(self.config)
        expected = os.path.expanduser('~/tmp')
        self.assertEqual(expected, artifact_dir)

    def test_get_project_dir(self):
        expected_artifact_dir = os.path.expanduser('~/tmp')
        project_name = config_utils.get_project_name(self.config)
        expected = "{}/{}/{}".format(
            expected_artifact_dir, consts.PROJ_DIR_NAME, project_name)

        proj_dir = config_utils.get_project_artifact_dir(self.config)
        self.assertEqual(expected, proj_dir)

    def test_get_kubespray_dir(self):
        expected_artifact_dir = os.path.expanduser('~/tmp')
        expected = "{}/{}".format(expected_artifact_dir,
                                  consts.KUBESPRAY_FOLDER_NAME)

        proj_dir = config_utils.get_kubespray_dir(self.config)
        self.assertEqual(expected, proj_dir)

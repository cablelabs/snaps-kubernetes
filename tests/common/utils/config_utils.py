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
    Tests for snaps_k8s.common.utils.config_utils.py
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

    def test_is_logging_enabled(self):
        """
        Tests to ensure that different string and boolean values return their
        expected values
        """
        this_cfg = {}
        this_cfg.update(self.config)

        this_cfg[consts.K8S_KEY][consts.ENABLE_LOG_KEY] = True
        self.assertTrue(config_utils.is_logging_enabled(self.config))

        this_cfg[consts.K8S_KEY][consts.ENABLE_LOG_KEY] = 'True'
        self.assertTrue(config_utils.is_logging_enabled(self.config))

        this_cfg[consts.K8S_KEY][consts.ENABLE_LOG_KEY] = 'true'
        self.assertTrue(config_utils.is_logging_enabled(self.config))

        this_cfg[consts.K8S_KEY][consts.ENABLE_LOG_KEY] = 'yes'
        self.assertTrue(config_utils.is_logging_enabled(self.config))

        this_cfg[consts.K8S_KEY][consts.ENABLE_LOG_KEY] = 'foo'
        self.assertFalse(config_utils.is_logging_enabled(self.config))

        this_cfg[consts.K8S_KEY][consts.ENABLE_LOG_KEY] = False
        self.assertFalse(config_utils.is_logging_enabled(self.config))

        this_cfg[consts.K8S_KEY][consts.ENABLE_LOG_KEY] = 'False'
        self.assertFalse(config_utils.is_logging_enabled(self.config))

        this_cfg[consts.K8S_KEY][consts.ENABLE_LOG_KEY] = 'false'
        self.assertFalse(config_utils.is_logging_enabled(self.config))

        this_cfg[consts.K8S_KEY][consts.ENABLE_LOG_KEY] = 'no'
        self.assertFalse(config_utils.is_logging_enabled(self.config))

        this_cfg[consts.K8S_KEY][consts.ENABLE_LOG_KEY] = None
        self.assertFalse(config_utils.is_logging_enabled(self.config))

    def test_get_log_level(self):
        """
        Ensures that the logging level is getting properly parsed
        """
        expected_log_level = self.config[consts.K8S_KEY][consts.LOG_LEVEL_KEY]
        log_level = config_utils.get_log_level(self.config)
        self.assertEqual(expected_log_level, log_level)

    def test_get_logging_port(self):
        """
        Ensures that the port returned is what is expected and is always a
        string
        """
        expected_port = self.config[consts.K8S_KEY][consts.LOG_PORT_KEY]
        port = config_utils.get_logging_port(self.config)
        self.assertEqual(expected_port, port)

        # tests that a numeric value is returned as a string
        this_cfg = {}
        this_cfg.update(self.config)
        this_cfg[consts.K8S_KEY][consts.LOG_PORT_KEY] = 1000
        port = config_utils.get_logging_port(this_cfg)
        self.assertEqual('1000', port)

    def test_is_cpu_alloc(self):
        """
        Tests to ensure that different string and boolean values return their
        expected values
        """
        this_cfg = {}
        this_cfg.update(self.config)

        this_cfg[consts.K8S_KEY][consts.CPU_ALLOC_KEY] = True
        self.assertTrue(config_utils.is_cpu_alloc(self.config))

        this_cfg[consts.K8S_KEY][consts.CPU_ALLOC_KEY] = 'True'
        self.assertTrue(config_utils.is_cpu_alloc(self.config))

        this_cfg[consts.K8S_KEY][consts.CPU_ALLOC_KEY] = 'true'
        self.assertTrue(config_utils.is_cpu_alloc(self.config))

        this_cfg[consts.K8S_KEY][consts.CPU_ALLOC_KEY] = 'yes'
        self.assertTrue(config_utils.is_cpu_alloc(self.config))

        this_cfg[consts.K8S_KEY][consts.CPU_ALLOC_KEY] = 'foo'
        self.assertFalse(config_utils.is_cpu_alloc(self.config))

        this_cfg[consts.K8S_KEY][consts.CPU_ALLOC_KEY] = False
        self.assertFalse(config_utils.is_cpu_alloc(self.config))

        this_cfg[consts.K8S_KEY][consts.CPU_ALLOC_KEY] = 'False'
        self.assertFalse(config_utils.is_cpu_alloc(self.config))

        this_cfg[consts.K8S_KEY][consts.CPU_ALLOC_KEY] = 'false'
        self.assertFalse(config_utils.is_cpu_alloc(self.config))

        this_cfg[consts.K8S_KEY][consts.CPU_ALLOC_KEY] = 'no'
        self.assertFalse(config_utils.is_cpu_alloc(self.config))

        this_cfg[consts.K8S_KEY][consts.CPU_ALLOC_KEY] = None
        self.assertFalse(config_utils.is_cpu_alloc(self.config))

    def test_is_metrics_server(self):
        """
        Tests to ensure that different string and boolean values return their
        expected values
        """
        this_cfg = {}
        this_cfg.update(self.config)

        this_cfg[consts.K8S_KEY][consts.METRICS_SERVER_KEY] = True
        self.assertTrue(config_utils.is_metrics_server_enabled(self.config))

        this_cfg[consts.K8S_KEY][consts.METRICS_SERVER_KEY] = 'True'
        self.assertTrue(config_utils.is_metrics_server_enabled(self.config))

        this_cfg[consts.K8S_KEY][consts.METRICS_SERVER_KEY] = 'true'
        self.assertTrue(config_utils.is_metrics_server_enabled(self.config))

        this_cfg[consts.K8S_KEY][consts.METRICS_SERVER_KEY] = 'yes'
        self.assertTrue(config_utils.is_metrics_server_enabled(self.config))

        this_cfg[consts.K8S_KEY][consts.METRICS_SERVER_KEY] = 'foo'
        self.assertFalse(config_utils.is_metrics_server_enabled(self.config))

        this_cfg[consts.K8S_KEY][consts.METRICS_SERVER_KEY] = False
        self.assertFalse(config_utils.is_metrics_server_enabled(self.config))

        this_cfg[consts.K8S_KEY][consts.METRICS_SERVER_KEY] = 'False'
        self.assertFalse(config_utils.is_metrics_server_enabled(self.config))

        this_cfg[consts.K8S_KEY][consts.METRICS_SERVER_KEY] = 'false'
        self.assertFalse(config_utils.is_metrics_server_enabled(self.config))

        this_cfg[consts.K8S_KEY][consts.METRICS_SERVER_KEY] = 'no'
        self.assertFalse(config_utils.is_metrics_server_enabled(self.config))

        this_cfg[consts.K8S_KEY][consts.METRICS_SERVER_KEY] = None
        self.assertFalse(config_utils.is_metrics_server_enabled(self.config))

    def test_get_password(self):
        node_confs = config_utils.get_node_configs(self.config)
        for node_conf in node_confs:
            password = config_utils.get_node_password(
                self.config, node_conf[consts.HOST_KEY][consts.HOSTNAME_KEY])
            self.assertEqual('password', password)

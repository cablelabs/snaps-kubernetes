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

import snaps_k8s.ansible_p.ansible_utils.ansible_playbook_launcher as apbl


class AnsibleLauncherTests(unittest.TestCase):
    def test_extra_var_string(self):
        var_dict = {'foo': 'bar', 'hello': 'world', 'goodbye': 'avoir'}
        var_str = apbl.create_extra_var_str(var_dict)
        logger.info(var_str)
        self.assertTrue(var_str.startswith('--extra_vars=\'{'))
        self.assertTrue('"foo":"bar"' in var_str)
        self.assertTrue('"hello":"world"' in var_str)
        self.assertTrue(var_str.endswith('}\''))

    def test_foo(self):
        "INFO:ansible_playbook_operations:ansible-playbook  /tmp/snaps-kubernetes/snaps_k8s/ansible_p/commission/kubernetes/playbooks/deploy_mode/k8/setup_k8.yaml --extra_vars='{\"target\":\"10.1.0.12\",\"SRC_PACKAGE_PATH\":\"/tmp/snaps-kubernetes/snaps_k8s/packages/source/inventory/\",\"APT_ARCHIVES_SRC\":\"/var/cache/apt/archives/\",\"VARIABLE_FILE\":\"/tmp/snaps-kubernetes/snaps_k8s/ansible_p/ansible_utils/variable.yaml\",\"host_name\":\"minion\",\"registry_port\":\"4386\",\"PROXY_DATA_FILE\":\"/tmp/snaps-kubernetes/snaps_k8s/ansible_p/ansible_utils/proxy_data.yaml\"}'"
        foo = {"target": "10.1.0.12",
               "SRC_PACKAGE_PATH": "/tmp/snaps-kubernetes/snaps_k8s/packages/source/inventory/",
               "APT_ARCHIVES_SRC": "/var/cache/apt/archives/",
               "VARIABLE_FILE": "/tmp/snaps-kubernetes/snaps_k8s/ansible_p/ansible_utils/variable.yaml",
               "host_name": "minion", "registry_port": "4386",
               "PROXY_DATA_FILE": "/tmp/snaps-kubernetes/snaps_k8s/ansible_p/ansible_utils/proxy_data.yaml"}
        logger.info(foo)

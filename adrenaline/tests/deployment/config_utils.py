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
import uuid

import os
import pkg_resources
from snaps import file_utils
from snaps_k8s.common.utils import validation_utils

from snaps_adrenaline.deployment import config_utils
from snaps_adrenaline.playbooks import consts


class ConfigUtilsTests(unittest.TestCase):

    def __init__(self, arg):
        super(self.__class__, self).__init__(arg)
        self.conf_file = None

    def tearDown(self):
        if self.conf_file:
            os.remove(self.conf_file.name)

    def test_convert_and_save_conf(self):
        """
        Exercises the config_utils.persist_config_to_file() function
        """
        boot_conf_file = pkg_resources.resource_filename(
            'tests.deployment.boot.conf', 'boot.yaml')
        boot_conf = file_utils.read_yaml(boot_conf_file)

        conf_file_path = "/tmp/boot-conf-{}.yaml".format(uuid.uuid4())

        self.conf_file = config_utils.persist_config_to_file(
            boot_conf, conf_file_path)
        self.assertIsNotNone(self.conf_file)
        self.assertTrue(os.path.exists(self.conf_file.name))

        conf_check = file_utils.read_yaml(self.conf_file.name)
        self.assertEqual(boot_conf, conf_check)

    def test_get_node_ips(self):
        """
        Exercises the config_utils.get_node_ips_from_config() function
        """
        boot_conf_file = pkg_resources.resource_filename(
            'tests.deployment.boot.conf', 'boot.yaml')
        boot_conf = file_utils.read_yaml(boot_conf_file)
        self.assertIsNotNone(boot_conf)

        ips = config_utils.get_node_ips_from_config(boot_conf)
        self.assertTrue('10.0.0.11' in ips)
        self.assertTrue('10.0.0.12' in ips)
        self.assertFalse('10.0.0.10' in ips)
        self.assertFalse('10.0.0.13' in ips)

    def test_get_first_master_node_ip(self):
        """
        Exercises the config_utils.get_first_master_ip() function
        """
        boot_conf_file = pkg_resources.resource_filename(
            'tests.deployment.boot.conf', 'boot.yaml')
        boot_conf = file_utils.read_yaml(boot_conf_file)
        self.assertIsNotNone(boot_conf)

        hb_conf_file = pkg_resources.resource_filename(
            'tests.deployment.kubernetes.conf', 'k8s.yaml')
        hb_conf = file_utils.read_yaml(hb_conf_file)
        self.assertIsNotNone(hb_conf)

        ip = config_utils.get_node_ip(
            boot_conf, hb_conf['docker']['repo_host'])
        self.assertIsNotNone(ip)
        self.assertEqual('10.0.0.11', ip)

    def test_get_node_user(self):
        """
        Exercises the config_utils.get_node_user() function
        """
        boot_conf_file = pkg_resources.resource_filename(
            'tests.deployment.boot.conf', 'boot.yaml')
        boot_conf = file_utils.read_yaml(boot_conf_file)
        self.assertIsNotNone(boot_conf)

        user = config_utils.get_node_user(boot_conf)
        self.assertEqual('foo_user', user)

    def test_get_node_password(self):
        """
        Exercises the config_utils.get_node_pass() function
        """
        boot_conf_file = pkg_resources.resource_filename(
            'tests.deployment.boot.conf', 'boot.yaml')
        boot_conf = file_utils.read_yaml(boot_conf_file)
        self.assertIsNotNone(boot_conf)

        password = config_utils.get_node_pass(boot_conf)
        self.assertEqual('Pa$$w0rd', password)

    def test_get_k8s_conf_dict(self):
        """
        Exercises the config_utils.k8s_conf_dict() function
        """
        boot_conf_file = pkg_resources.resource_filename(
            'tests.deployment.boot.conf', 'boot.yaml')
        boot_conf = file_utils.read_yaml(boot_conf_file)
        hb_conf_file = pkg_resources.resource_filename(
            'tests.deployment.kubernetes.conf', 'k8s.yaml')
        hb_conf = file_utils.read_yaml(hb_conf_file)

        k8s_conf = config_utils.k8s_conf_dict(boot_conf, hb_conf)
        kube_dict = k8s_conf['kubernetes']
        self.assertIsNotNone(kube_dict.get('api_host'))
        self.assertEquals('foo.com:5555', kube_dict['api_host'])
        validation_utils.validate_deployment_file(k8s_conf)

        self.assertIsNotNone(kube_dict)

        self.assertEquals(
            'v{}'.format(consts.DFLT_K8S_VERSION), kube_dict['version'])
        self.assertEquals(
            consts.DFLT_KUBESPRAY_URL, kube_dict['kubespray_url'])
        self.assertEquals(
            consts.DFLT_KUBESPRAY_BRANCH, kube_dict['kubespray_branch'])

        self.assertIsNotNone(kube_dict['Docker_Repo'])
        docker_repo = kube_dict['Docker_Repo']
        self.assertEqual('10.0.0.11', docker_repo['ip'])
        self.assertEqual('password', docker_repo['password'])
        self.assertEqual(4000, docker_repo['port'])
        self.assertEqual('root', docker_repo['user'])

        self.assertIsNotNone(kube_dict['Networks'])
        networks = kube_dict['Networks']
        default_net = networks[0]['Default_Network']
        self.assertEqual('true', default_net['isMaster'])
        self.assertEqual('default-network', default_net['network_name'])
        self.assertEqual('contiv', default_net['networking_plugin'])
        self.assertEqual('10.251.0.0/16', default_net['pod_subnet'])
        self.assertEqual('10.241.0.0/16', default_net['service_subnet'])

        multis_nets = networks[1]['Multus_network']
        self.assertIsNotNone(multis_nets)
        self.assertEqual(2, len(multis_nets))
        self.assertTrue('CNI' in multis_nets[0])
        self.assertTrue('CNI_Configuration' in multis_nets[1])

        cnis = multis_nets[0]['CNI']
        self.assertEqual(4, len(cnis))
        self.assertTrue('macvlan' in cnis)
        self.assertTrue('weave' in cnis)
        self.assertTrue('flannel' in cnis)
        self.assertTrue('dhcp' in cnis)

        cni_conf = multis_nets[1]['CNI_Configuration']
        self.assertEqual(3, len(cni_conf))

        self.assertIsNotNone(kube_dict['Persistent_Volumes'])
        persist_vols = kube_dict['Persistent_Volumes']
        self.assertEqual(2, len(persist_vols))
        self.assertFalse('Ceph_Volume' in persist_vols)
        self.assertTrue('Host_Volume' in persist_vols)
        host_vols = persist_vols['Host_Volume']
        self.assertEqual(2, len(host_vols))

        self.assertTrue('claim_parameters' in host_vols[0])
        claim_params1 = host_vols[0]['claim_parameters']
        self.assertEqual(2, len(claim_params1))
        self.assertTrue('Claim_name' in claim_params1)
        self.assertEqual('claim5', claim_params1['Claim_name'])
        self.assertTrue('storage' in claim_params1)
        self.assertEqual('4Gi', claim_params1['storage'])

        claim_params2 = host_vols[1]['claim_parameters']
        self.assertEqual(2, len(claim_params2))
        self.assertTrue('Claim_name' in claim_params2)
        self.assertEqual('claim6', claim_params2['Claim_name'])
        self.assertTrue('storage' in claim_params2)
        self.assertEqual('5Gi', claim_params2['storage'])

        self.assertIsNotNone(kube_dict['Project_name'])
        self.assertEqual('bar', kube_dict['Project_name'])

        self.assertIsNotNone(kube_dict['basic_authentication'])
        basic_auth = kube_dict['basic_authentication']
        self.assertEqual(1, len(basic_auth))
        self.assertTrue('user' in basic_auth[0])
        basic_auth_user = basic_auth[0]['user']
        self.assertTrue('user_id' in basic_auth_user)
        self.assertEqual('admin', basic_auth_user['user_id'])
        self.assertTrue('user_name' in basic_auth_user)
        self.assertEqual('admin', basic_auth_user['user_name'])
        self.assertTrue('user_password' in basic_auth_user)
        self.assertEqual('admin', basic_auth_user['user_password'])

        self.assertIsNotNone(kube_dict['enable_metrics_server'])
        self.assertTrue(kube_dict['enable_metrics_server'])

        self.assertIsNotNone(kube_dict['node_configuration'])
        node_configs = kube_dict['node_configuration']
        self.assertEqual(2, len(node_configs))
        self.assertTrue('host' in node_configs[0])
        node_config1 = node_configs[0]['host']
        self.assertEqual(8, len(node_config1))
        self.assertTrue('hostname' in node_config1)
        self.assertEqual('master1', node_config1['hostname'])
        self.assertTrue('ip' in node_config1)
        self.assertEqual('10.0.0.11', node_config1['ip'])
        self.assertTrue('label_key' in node_config1)
        self.assertEqual('zone', node_config1['label_key'])
        self.assertTrue('label_value' in node_config1)
        self.assertEqual('master1', node_config1['label_value'])
        self.assertTrue('node_type' in node_config1)
        self.assertEqual('master', node_config1['node_type'])
        self.assertTrue('password' in node_config1)
        self.assertEqual('Pa$$w0rd', node_config1['password'])
        self.assertTrue('registry_port' in node_config1)
        self.assertEqual(2376, node_config1['registry_port'])
        self.assertTrue('user' in node_config1)
        self.assertEqual('root', node_config1['user'])
        
        self.assertTrue('host' in node_configs[1])
        node_config2 = node_configs[1]['host']
        self.assertEqual(8, len(node_config2))
        self.assertTrue('hostname' in node_config2)
        self.assertEqual('minion1', node_config2['hostname'])
        self.assertTrue('ip' in node_config2)
        self.assertEqual('10.0.0.12', node_config2['ip'])
        self.assertTrue('label_key' in node_config2)
        self.assertEqual('zone', node_config2['label_key'])
        self.assertTrue('label_value' in node_config2)
        self.assertEqual('minion1', node_config2['label_value'])
        self.assertTrue('node_type' in node_config2)
        self.assertEqual('minion', node_config2['node_type'])
        self.assertTrue('password' in node_config2)
        self.assertEqual('Pa$$w0rd', node_config2['password'])
        self.assertTrue('registry_port' in node_config2)
        self.assertEqual(4386, node_config2['registry_port'])
        self.assertTrue('user' in node_config2)
        self.assertEqual('root', node_config2['user'])

        self.assertIsNotNone(kube_dict['proxies'])
        proxies = kube_dict['proxies']
        self.assertTrue('ftp_proxy' in proxies)
        self.assertEqual('', proxies['ftp_proxy'])
        self.assertTrue('http_proxy' in proxies)
        self.assertEqual('', proxies['http_proxy'])
        self.assertTrue('https_proxy' in proxies)
        self.assertEqual('', proxies['https_proxy'])
        self.assertTrue('no_proxy' in proxies)
        self.assertEqual('127.0.0.1,localhost,', proxies['no_proxy'])

    def test_get_k8s_version(self):
        """
        Exercises the config_utils.get_k8s_version() function
        """
        boot_conf_file = pkg_resources.resource_filename(
            'tests.deployment.boot.conf', 'boot.yaml')
        boot_conf = file_utils.read_yaml(boot_conf_file)
        hb_conf_file = pkg_resources.resource_filename(
            'tests.deployment.kubernetes.conf', 'k8s.yaml')
        hb_conf = file_utils.read_yaml(hb_conf_file)
        k8s_conf = config_utils.k8s_conf_dict(boot_conf, hb_conf)

        version_long = config_utils.get_k8s_version(k8s_conf)
        self.assertEqual('1.12.5', version_long)

        version_short = config_utils.get_k8s_version(
            k8s_conf, maj_min_only=True)
        self.assertEqual('1.12', version_short)

        k8s_conf['kubernetes']['version'] = '9'
        with self.assertRaises(Exception):
            config_utils.get_k8s_version(k8s_conf)

    def test_get_master_node_ips(self):
        """
        Exercises the config_utils.get_master_node_ips() function
        """
        boot_conf_file = pkg_resources.resource_filename(
            'tests.deployment.boot.conf', 'boot.yaml')
        boot_conf = file_utils.read_yaml(boot_conf_file)
        hb_conf_file = pkg_resources.resource_filename(
            'tests.deployment.kubernetes.conf', 'k8s.yaml')
        hb_conf = file_utils.read_yaml(hb_conf_file)

        master_ips = config_utils.get_master_node_ips(boot_conf, hb_conf)
        self.assertEqual(1, len(master_ips))
        self.assertTrue('10.0.0.11' in master_ips)

    def test_get_minion_node_ips(self):
        """
        Exercises the config_utils.get_master_node_ips() function
        """
        boot_conf_file = pkg_resources.resource_filename(
            'tests.deployment.boot.conf', 'boot.yaml')
        boot_conf = file_utils.read_yaml(boot_conf_file)
        hb_conf_file = pkg_resources.resource_filename(
            'tests.deployment.kubernetes.conf', 'k8s.yaml')
        hb_conf = file_utils.read_yaml(hb_conf_file)

        minion_ips = config_utils.get_minion_node_ips(boot_conf, hb_conf)
        self.assertEqual(1, len(minion_ips))
        self.assertTrue('10.0.0.12' in minion_ips)

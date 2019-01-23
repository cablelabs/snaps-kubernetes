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
        self.node_list = self.config[consts.K8S_KEY][consts.NODE_CONF_KEY]
        self.network_list = self.config[consts.K8S_KEY][consts.NETWORKS_KEY]
        self.persis_vol = self.config[consts.K8S_KEY][consts.PERSIS_VOL_KEY]

    def test_get_proxy_dict(self):
        """
        Ensures proxy values are properly parsed
        """
        proxy_dict = config_utils.get_proxy_dict(self.config)
        expected = self.config[consts.K8S_KEY][consts.PROXIES_KEY]
        self.assertEqual(expected, proxy_dict)

    def test_get_networks(self):
        """
        Ensures network values are properly parsed
        """
        networks_data = config_utils.get_networks(self.config)
        expected = self.config[consts.K8S_KEY][consts.NETWORKS_KEY]
        self.assertEqual(expected, networks_data)

    def test_get_multus_network(self):
        """
        Ensures MuLtus network configuration is properly parsed
        """
        multus_networks_data = config_utils.get_multus_network(self.config)
        mult_config = self.network_list[1][consts.MULTUS_NET_KEY]
        self.assertEqual(mult_config, multus_networks_data)

    def test_get_multus_net_elems(self):
        """
        Ensures Multus CNI elements are properly parsed
        """
        multus_net_elems = config_utils.get_multus_net_elems(self.config)
        expected = self.network_list[1][consts.MULTUS_NET_KEY][0][consts.MULTUS_CNI_KEY]
        self.assertEqual(expected, multus_net_elems)

    def test_get_multus_cni_cfgs(self):
        """
        Ensures Multus CNI element configuration is properly parsed
        """
        multus_cni_cfgs = config_utils.get_multus_cni_cfgs(self.config)
        expected = self.network_list[1][consts.MULTUS_NET_KEY][1][consts.MULTUS_CNI_CONFIG_KEY]
        self.assertEqual(expected, multus_cni_cfgs)

    def test_get_multus_cni_flannel_cfgs(self):
        """
        Ensures Flannel network values are properly parsed
        """
        cni_cfg = config_utils.get_multus_cni_flannel_cfgs(self.config)
        multus_cni = self.network_list[1][consts.MULTUS_NET_KEY][1][consts.MULTUS_CNI_CONFIG_KEY]
        expected = multus_cni[0][consts.FLANNEL_NET_TYPE]
        self.assertEqual(expected, cni_cfg)

    def test_multus_cni_macvlan_cfgs(self):
        """
        Ensures Macvlan network values are properly parsed
        """
        macvlan_cfg = config_utils.get_multus_cni_macvlan_cfgs(self.config)
        multus_cni = self.network_list[1][consts.MULTUS_NET_KEY][1][consts.MULTUS_CNI_CONFIG_KEY]
        expected = multus_cni[2][consts.MACVLAN_NET_TYPE]
        self.assertEqual(expected, macvlan_cfg)

    def test_multus_cni_sriov_cfgs(self):
        """
        Ensures SRIOV network values are properly parsed
        """
        sriov_cfg = config_utils.get_multus_cni_sriov_cfgs(self.config)
        multus_cni = self.network_list[1][consts.MULTUS_NET_KEY][1][consts.MULTUS_CNI_CONFIG_KEY]
        expected = multus_cni[3][consts.SRIOV_NET_TYPE]
        self.assertEqual(expected, sriov_cfg)

    def test_get_multus_cni_weave_cfgs(self):
        """
        Ensures Weave network values are properly parsed
        """
        weave_cfg = config_utils.get_multus_cni_weave_cfgs(self.config)
        multus_cni = self.network_list[1][consts.MULTUS_NET_KEY][1][consts.MULTUS_CNI_CONFIG_KEY]
        expected = multus_cni[1][consts.WEAVE_NET_TYPE]
        self.assertEqual(expected, weave_cfg)

    def test_is_multus_cni_enabled(self):
        """
        Ensures Multus CNI status is properly parsed
        """
        multus_cni = config_utils.is_multus_cni_enabled(self.config)
        expected_multus_cni = False
        cni_list = self.network_list[1][consts.MULTUS_NET_KEY][0][consts.MULTUS_CNI_KEY]
        if (consts.SRIOV_TYPE or consts.FLANNEL_TYPE or consts.WEAVE_TYPE or consts.MACVLAN_TYPE) in cni_list:
            expected_multus_cni = True
        self.assertEqual(expected_multus_cni, multus_cni)

    def test_get_default_network(self):
        """
        Ensures default network values are properly parsed
        """
        default_network = config_utils.get_default_network(self.config)
        expected = self.network_list[0][consts.DFLT_NET_KEY]
        self.assertEqual(expected, default_network)

    def test_get_service_subnet(self):
        """
        Ensures service subnet value of the default network is properly parsed
        """
        service_subnet = config_utils.get_service_subnet(self.config)
        expected = self.network_list[0][consts.DFLT_NET_KEY][consts.SRVC_SUB_KEY]
        self.assertEqual(expected, service_subnet)

    def test_get_networking_plugin(self):
        """
        Ensures networking plugin value of the default network is properly parsed
        """
        networking_plugin = config_utils.get_networking_plugin(self.config)
        expected = self.network_list[0][consts.DFLT_NET_KEY][consts.NET_PLUGIN_KEY]
        self.assertEqual(expected, networking_plugin)

    def test_get_pod_subnet(self):
        """
        Ensures pod subnet value of the default network is properly parsed
        """
        pod_subnet = config_utils.get_pod_subnet(self.config)
        expected = self.network_list[0][consts.DFLT_NET_KEY][consts.POD_SUB_KEY]
        self.assertEqual(expected, pod_subnet)

    def test_get_version(self):
        """
        Ensures Kubernetes version is properly parsed
        """
        version_data = config_utils.get_version(self.config)
        expected = self.config[consts.K8S_KEY][consts.K8_VER_KEY]
        self.assertEqual(expected, version_data)

    def test_get_ha_config(self):
        """
        Ensures HA configuration values are properly parsed
        """
        ha_config = config_utils.get_ha_config(self.config)
        expected = self.config[consts.K8S_KEY][consts.HA_CONFIG_KEY]
        self.assertEqual(expected, ha_config)

    def test_get_ha_lb_ips(self):
        """
        Ensures HA loadbalancer IP values are properly parsed
        """
        ha_lb_ips = config_utils.get_ha_lb_ips(self.config)
        expected_lb_ips_list = list()
        for config_element in self.config[consts.K8S_KEY][consts.HA_CONFIG_KEY]:
            expected_lb_ips_list.append(config_element[consts.HA_API_EXT_LB_KEY][consts.IP_KEY])
        self.assertEqual(expected_lb_ips_list, ha_lb_ips)

    def test_get_node_configs(self):
        """
        Ensures node configuration settings are properly parsed
        """
        node_configs = config_utils.get_node_configs(self.config)
        expected = self.config[consts.K8S_KEY][consts.NODE_CONF_KEY]
        self.assertEqual(expected, node_configs)

    def test_get_hostname_ips_dict(self):
        """
        Ensures hostnames and IPs of the nodes are properly parsed
        """
        hostname_ips_dict = config_utils.get_hostname_ips_dict(self.config)
        hostname_ips = dict()
        for node in self.node_list:
            hostname_ips[node[consts.HOST_KEY][consts.HOSTNAME_KEY]] = node[consts.HOST_KEY][consts.IP_KEY]
        self.assertEqual(hostname_ips, hostname_ips_dict)

    def test_get_host_reg_port_dict(self):
        """
        Ensures hostnames and registry port value of the nodes are properly parsed
        """
        host_reg_port_dict = config_utils.get_host_reg_port_dict(self.config)
        host_reg_port = dict()
        for node in self.node_list:
            host_reg_port[node[consts.HOST_KEY][consts.HOSTNAME_KEY]] = node[consts.HOST_KEY][consts.REG_PORT_KEY]
        self.assertEqual(host_reg_port, host_reg_port_dict)

    def test_get_host_ips(self):
        """
        Ensures the list of host IPs are properly parsed
        """
        host_ips = config_utils.get_host_ips(self.config)
        host_ips_cfg = list()
        for node in self.node_list:
            host_ips_cfg.append(node[consts.HOST_KEY][consts.IP_KEY])
        self.assertEqual(host_ips_cfg, host_ips)

    def test_get_hosts(self):
        """
        Ensures the list of hostnames of the configured nodes are properly parsed
        """
        hosts = config_utils.get_hosts(self.config)
        host_cfg = list()
        for node in self.node_list:
            host_cfg.append(node[consts.HOST_KEY][consts.HOSTNAME_KEY])
        self.assertEqual(host_cfg, hosts)

    def test_get_basic_auth(self):
        """
        Ensures the basic authentication settings are properly parsed
        """
        basic_auth = config_utils.get_basic_auth(self.config)
        expected = self.config[consts.K8S_KEY][consts.BASIC_AUTH_KEY]
        self.assertEqual(expected, basic_auth)

    def test_get_project_name(self):
        """
        Ensures the project name value is properly parsed
        """
        project_name = config_utils.get_project_name(self.config)
        expected = self.config[consts.K8S_KEY][consts.PROJECT_NAME_KEY]
        self.assertEqual(expected, project_name)

    def test_get_artifact_dir(self):
        """
        Ensures the artifact directory location is properly parsed
        """
        artifact_dir = config_utils.get_artifact_dir(self.config)
        expected = os.path.expanduser('~/tmp')
        self.assertEqual(expected, artifact_dir)

    def test_get_project_dir(self):
        """
        Ensures the project location is properly parsed
        """
        expected_artifact_dir = os.path.expanduser('~/tmp')
        project_name = config_utils.get_project_name(self.config)
        expected = "{}/{}/{}".format(
            expected_artifact_dir, consts.PROJ_DIR_NAME, project_name)

        proj_dir = config_utils.get_project_artifact_dir(self.config)
        self.assertEqual(expected, proj_dir)

    def test_get_kubespray_dir(self):
        """
        Ensures the kubespray location is properly parsed
        """
        expected_artifact_dir = os.path.expanduser('~/tmp')
        expected = "{}/{}".format(expected_artifact_dir,
                                  consts.KUBESPRAY_FOLDER_NAME)

        proj_dir = config_utils.get_kubespray_dir(self.config)
        self.assertEqual(expected, proj_dir)

    def test_get_docker_repo(self):
        """
        Ensures the Docker Repo settings are properly parsed
        """
        docker_repo = config_utils.get_docker_repo(self.config)
        expected = self.config[consts.K8S_KEY][consts.DOCKER_REPO_KEY]
        self.assertEqual(expected, docker_repo)

    def test_get_git_branch(self):
        """
        Ensures the Git branch settings are properly parsed
        """
        git_branch = config_utils.get_git_branch(self.config)
        expected = self.config[consts.K8S_KEY][consts.GIT_BRANCH_KEY]
        self.assertEqual(expected, git_branch)

    def test_get_persis_vol(self):
        """
        Ensures the Persistent Volume settings are properly parsed
        """
        persis_vol = config_utils.get_persist_vol(self.config)
        expected = self.persis_vol
        self.assertEqual(expected, persis_vol)

    def test_get_ceph_vol(self):
        """
        Ensures the Ceph Volume settings are properly parsed
        """
        ceph_vol = config_utils.get_ceph_vol(self.config)
        expected = self.persis_vol[consts.CEPH_VOLUME_KEY]
        self.assertEqual(expected, ceph_vol)

    def test_get_ceph_hosts(self):
        """
        Ensures the Ceph host settings are properly parsed
        """
        ceph_hosts = config_utils.get_ceph_hosts(self.config)
        ceph_hosts_cfg = list()
        if self.config[consts.K8S_KEY][consts.PERSIS_VOL_KEY][consts.CEPH_VOLUME_KEY]:
            for ceph_host in self.persis_vol[consts.CEPH_VOLUME_KEY]:
                if consts.HOST_KEY in ceph_host:
                    ceph_hosts_cfg.append(ceph_host[consts.HOST_KEY])
        self.assertEqual(ceph_hosts_cfg, ceph_hosts)

    def test_get_ceph_hosts_info(self):
        """
        Ensures the hostname, IP and type value of the Ceph hosts are properly parsed
        """
        ceph_hosts_info = config_utils.get_ceph_hosts_info(self.config)
        ceph_hosts_info_cfg = list()
        for ceph_host in self.persis_vol[consts.CEPH_VOLUME_KEY]:
            ceph_hosts_info_cfg.append((ceph_host[consts.HOST_KEY][consts.HOSTNAME_KEY],
                                        ceph_host[consts.HOST_KEY][consts.IP_KEY],
                                        ceph_host[consts.HOST_KEY][consts.NODE_TYPE_KEY]))
        self.assertEqual(ceph_hosts_info_cfg, ceph_hosts_info)

    def test_get_ceph_ctrls(self):
        """
        Ensures the Ceph control host configuration is properly parsed
        """
        ceph_ctrls = config_utils.get_ceph_ctrls(self.config)
        ceph_ctrls_cfg = list()
        for ceph_host in self.persis_vol[consts.CEPH_VOLUME_KEY]:
            if ceph_host[consts.HOST_KEY][consts.NODE_TYPE_KEY] == consts.CEPH_CTRL_TYPE:
                ceph_ctrls_cfg.append(ceph_host[consts.HOST_KEY])
        self.assertEqual(ceph_ctrls_cfg, ceph_ctrls)

    def test_get_ceph_ctrls_info(self):
        """
        Ensures the hostname, IP and type value of the Ceph control hosts are properly parsed
        """
        ceph_ctrls_info = config_utils.get_ceph_ctrls_info(self.config)
        ceph_ctrls_info_cfg = list()
        for ceph_host in self.persis_vol[consts.CEPH_VOLUME_KEY]:
            if ceph_host[consts.HOST_KEY][consts.NODE_TYPE_KEY] == consts.CEPH_CTRL_TYPE:
                ceph_ctrls_info_cfg.append((ceph_host[consts.HOST_KEY][consts.HOSTNAME_KEY],
                                            ceph_host[consts.HOST_KEY][consts.IP_KEY],
                                            ceph_host[consts.HOST_KEY][consts.NODE_TYPE_KEY]))
        self.assertEqual(ceph_ctrls_info_cfg, ceph_ctrls_info)

    def test_get_ceph_osds(self):
        """
        Ensures the Ceph OSD host settings are properly parsed
        """
        ceph_osds = config_utils.get_ceph_osds(self.config)
        ceph_osds_cfg = list()
        for ceph_host in self.persis_vol[consts.CEPH_VOLUME_KEY]:
            if ceph_host[consts.HOST_KEY][consts.NODE_TYPE_KEY] == consts.CEPH_OSD_TYPE:
                ceph_osds_cfg.append(ceph_host[consts.HOST_KEY])
        self.assertEqual(ceph_osds_cfg, ceph_osds)

    def test_get_ceph_osds_info(self):
        """
        Ensures the hostname, IP and type value of the Ceph OSD hosts are properly parsed
        """
        ceph_osds_info = config_utils.get_ceph_osds_info(self.config)
        ceph_osds_info_cfg = list()
        for ceph_host in self.persis_vol[consts.CEPH_VOLUME_KEY]:
            if ceph_host[consts.HOST_KEY][consts.NODE_TYPE_KEY] == consts.CEPH_OSD_TYPE:
                ceph_osds_info_cfg.append((ceph_host[consts.HOST_KEY][consts.HOSTNAME_KEY],
                                           ceph_host[consts.HOST_KEY][consts.IP_KEY],
                                           ceph_host[consts.HOST_KEY][consts.NODE_TYPE_KEY]))
        self.assertEqual(ceph_osds_info_cfg, ceph_osds_info)

    def test_get_host_vol(self):
        """
        Ensures the Host Volume settings are properly parsed
        """
        host_vol = config_utils.get_host_vol(self.config)
        expected = self.persis_vol[consts.HOST_VOL_KEY]
        self.assertEqual(expected, host_vol)

    def test_get_persist_vol_claims(self):
        """
        Ensures the Claim parameters of the Host Volume are properly parsed
        """
        persist_vol_claims = config_utils.get_persist_vol_claims(self.config)
        persist_vol_claims_cfg = list()
        for persist_vol in self.persis_vol[consts.HOST_VOL_KEY]:
            if consts.CLAIM_PARAMS_KEY in persist_vol:
                persist_vol_claims_cfg.append(persist_vol[consts.CLAIM_PARAMS_KEY])
        self.assertEqual(persist_vol_claims_cfg, persist_vol_claims)

    def test_get_first_master_host(self):
        """
        Ensures the hostname and IP of the first master host found in the config are properly parsed
        """
        hostname, ip = config_utils.get_first_master_host(self.config)
        for node in self.node_list:
            if node[consts.HOST_KEY][consts.NODE_TYPE_KEY] == consts.NODE_TYPE_MASTER:
                hostname_cfg, ip_cfg = node[consts.HOST_KEY][consts.HOSTNAME_KEY], node[consts.HOST_KEY][consts.IP_KEY]
                break
        self.assertItemsEqual((hostname_cfg, ip_cfg), (hostname, ip))

    def test_get_nodes_ip_name_type(self):
        """
        Ensures the hostname, IP and type value of all configured hosts are properly parsed
        """
        nodes_ip_name_type = config_utils.get_nodes_ip_name_type(self.config)
        nodes_ip_name_type_cfg = list()
        for node in self.node_list:
            nodes_ip_name_type_cfg.append((node[consts.HOST_KEY][consts.HOSTNAME_KEY],
                                           node[consts.HOST_KEY][consts.IP_KEY],
                                           node[consts.HOST_KEY][consts.NODE_TYPE_KEY]))
        self.assertEqual(nodes_ip_name_type_cfg, nodes_ip_name_type)

    def test_get_master_nodes_ip_name_type(self):
        """
        Ensures the hostname, IP and type value of all configured master hosts are properly parsed
        """
        master_ip_name_type = config_utils.get_master_nodes_ip_name_type(self.config)
        master_ip_name_type_cfg = list()
        for node in self.node_list:
            if node[consts.HOST_KEY][consts.NODE_TYPE_KEY] == consts.NODE_TYPE_MASTER:
                master_ip_name_type_cfg.append((node[consts.HOST_KEY][consts.HOSTNAME_KEY],
                                                node[consts.HOST_KEY][consts.IP_KEY],
                                                node[consts.HOST_KEY][consts.NODE_TYPE_KEY]))
        self.assertEqual(master_ip_name_type_cfg, master_ip_name_type)

    def test_get_master_node_ips(self):
        """
        Ensures the IP address of all configured master hosts are properly parsed
        """
        master_node_ips = config_utils.get_master_node_ips(self.config)
        master_node_ips_cfg = list()
        for node in self.node_list:
            if node[consts.HOST_KEY][consts.NODE_TYPE_KEY] == consts.NODE_TYPE_MASTER:
                master_node_ips_cfg.append(node[consts.HOST_KEY][consts.IP_KEY])
        self.assertEqual(master_node_ips_cfg, master_node_ips)

    def test_get_minion_nodes_ip_name_type(self):
        """
        Ensures the hostname, IP and type value of all configured minion hosts are properly parsed
        """
        minion_ip_name_type = config_utils.get_minion_nodes_ip_name_type(self.config)
        minion_ip_name_type_cfg = list()
        for node in self.node_list:
            if node[consts.HOST_KEY][consts.NODE_TYPE_KEY] == consts.NODE_TYPE_MINION:
                minion_ip_name_type_cfg.append((node[consts.HOST_KEY][consts.HOSTNAME_KEY],
                                                node[consts.HOST_KEY][consts.IP_KEY],
                                                node[consts.HOST_KEY][consts.NODE_TYPE_KEY]))
        self.assertEqual(minion_ip_name_type_cfg, minion_ip_name_type)

    def test_get_minion_node_ips(self):
        """
        Ensures the IP address of all configured minion hosts are properly parsed
        """
        minion_node_ips = config_utils.get_minion_node_ips(self.config)
        minion_node_ips_cfg = list()
        for node in self.node_list:
            if node[consts.HOST_KEY][consts.NODE_TYPE_KEY] == consts.NODE_TYPE_MINION:
                minion_node_ips_cfg.append(node[consts.HOST_KEY][consts.IP_KEY])
        self.assertItemsEqual(minion_node_ips_cfg, minion_node_ips)

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

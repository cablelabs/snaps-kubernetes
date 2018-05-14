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
# This script is responsible for deploying Aricent_Iaas environments and
# Kubernetes Services

import logging
import re
import subprocess
import time

import ansible_playbook_launcher as apbl
from snaps_k8s.common.consts import consts
from snaps_k8s.common.utils import file_utils

DEFAULT_REPLACE_EXTENSIONS = None

logger = logging.getLogger('deploy_ansible_configuration')


def provision_preparation(proxy_dict):
    """
    This method is responsible for writing the hosts info in ansible hosts file
    proxy inf in ansible proxy file
    : param proxy_dict: proxy data in the dictionary format
    : return ret :
    """

    # code which adds ip to the /etc/anisble/hosts file
    ret = True

    if proxy_dict:
        logger.debug("Adding proxies")
        proxy_file_in = open(consts.PROXY_DATA_FILE, "r+")
        proxy_file_in.seek(0)
        proxy_file_in.truncate()
        proxy_file_out = open(consts.PROXY_DATA_FILE, "w")
        proxy_file_out.write("---")
        proxy_file_out.write("\n")
        for key, value in proxy_dict.items():
            if value == '':
                value = "\"\""
            logger.info("" + key + ":" + value)
            logger.debug("Proxies added in file:" + key + ":" + value)
            proxy_file_out.write(key + ": " + str(value) + "\n")
        proxy_file_out.close()
        proxy_file_in.close()
        return ret


def clean_up_k8_addons(**k8_addon):
    """
    function to delete all addons : such as metrics server
    :param k8_addon:
    :return:
    """
    return_stmt = False
    hostname_map = k8_addon.get("hostname_map")
    host_node_type_map = k8_addon.get("host_node_type_map")
    for addon in k8_addon:
        if addon == "metrics_server" and k8_addon.get("metrics_server"):
            return_stmt = clean_up_metrics_server(hostname_map,
                                                  host_node_type_map)

    return return_stmt


def clean_up_k8(enable_istio, git_branch, enable_ambassador, ambassador_rbac,
                project_name):
    """
    This function is used for clean/Reset the kubernetes cluster
    """
    var_file = consts.VARIABLE_FILE
    master_hostname = get_host_master_name(project_name)
    host_name = master_hostname

    if enable_istio == "yes":
        ret_hosts = apbl.uninstall_istio(
            consts.UNINSTALL_ISTIO, host_name,
            consts.INVENTORY_SOURCE_FOLDER)
        if not ret_hosts:
            logger.error('FAILED IN INSTALLING FILE PLAY')
            exit(1)
    if enable_ambassador == "yes":
        ret_hosts = apbl.uninstall_ambassador(
            consts.UNINSTALL_AMBASSADOR, host_name,
            consts.INVENTORY_SOURCE_FOLDER, ambassador_rbac)
        if not ret_hosts:
            logger.error('FAILED IN INSTALLING FILE PLAY')
            exit(1)

    logger.info('EXECUTING CLEAN K8 CLUSTER PLAY')
    ret_hosts = apbl.clean_k8(
        consts.K8_CLEAN_UP, consts.INVENTORY_SOURCE_FOLDER, var_file,
        consts.PROXY_DATA_FILE, git_branch, project_name)
    if not ret_hosts:
        logger.error('FAILED IN CLEAN UP KUBERNETES CLUSTER ')
        exit(1)
    host_name_map_ip = get_hostname_ip_map_list(project_name)
    for host_name, ip in host_name_map_ip.items():
        logger.info('EXECUTING DELETE NODES PLAY')
        ret_hosts = apbl.delete_host_k8(
            consts.K8_REMOVE_NODE_K8, ip, host_name, consts.HOSTS_FILE,
            consts.ANSIBLE_HOSTS_FILE, var_file, project_name)
        if not ret_hosts:
            logger.error('FAILED IN DELTING NODE')
            exit(1)
    logger.info('EXECUTING REMOVE PROJECT FOLDER PLAY')
    ret_hosts = apbl.delete_project_folder(
        consts.K8_REMOVE_FOLDER, var_file,
        consts.INVENTORY_SOURCE_FOLDER, project_name)
    if not ret_hosts:
        logger.error('FAILED IN CLEAN UP KUBERNETES CLUSTER ')
        exit(1)

    return ret_hosts


def clean_up_k8_nodes(dynamic_hostname_map, project_name):
    """
    This function is used for clean/Reset the specific node of kubernet cluster
    : param host_name_list : list of all the host names
    """
    master_hostname = get_host_master_name(project_name)
    ret_hosts = False

    for host_name, ip in dynamic_hostname_map.items():
        logger.info('EXECUTING CLEAN K8 NODE PLAY')
        ret_hosts = apbl.dynamic_k8_nodes_delete(
            consts.K8_CLEAN_UP_NODES, host_name,
            consts.INVENTORY_SOURCE_FOLDER,
            consts.VARIABLE_FILE, consts.PROXY_DATA_FILE, master_hostname,
            project_name)
        if not ret_hosts:
            logger.error('FAILED IN DELTING NODE')
            exit(1)

        logger.info('EXECUTING REMOVE NODE FROM INVENTORY PLAY')
        ret_hosts = apbl.delete_node(
            consts.K8_DELETE_NODE, host_name,
            consts.INVENTORY_SOURCE_FOLDER,
            consts.VARIABLE_FILE, project_name)
        if not ret_hosts:
            logger.error('FAILED IN DELTING NODE')
            exit(1)
        logger.info(
            'EXECUTING REMOVE NODE FROM /etc/hosts and /etc/ansible/hosts'
            ' PLAY')
        ret_hosts = apbl.delete_host_k8(
            consts.K8_REMOVE_NODE_K8, ip, host_name, consts.HOSTS_FILE,
            consts.ANSIBLE_HOSTS_FILE, consts.VARIABLE_FILE, project_name)
        if not ret_hosts:
            logger.error('FAILED IN DELTING NODE')
            exit(1)
    return ret_hosts


def deploy_k8_nodes(host_name_list, dynamic_hostname_map,
                    dynamic_host_node_type_map, host_port_map, dynamic_hosts,
                    project_name, master_ip):
    """
    This function is used for deploy the specific node in  the kubernetes
    cluster
    TODO/REVIEW - First two parameters seem redundant
    : param host_name_list : list of all host name
    : param host_name_map : dictionary of all host name with ip map
    : param host_node_type_map : dictionary of all host name with node map
    """
    master_hostname = get_host_master_name(project_name)

    # TODO/FIXME - These can be run in parallel for each host
    for host_name, ip in dynamic_hostname_map.items():
        registry_port = host_port_map.get(host_name)
        logger.info('EXECUTING CONFIGURE NODE PLAY')
        ret_hosts = apbl.set_k8s_packages(
            consts.K8_SET_PACKAGES, ip, host_name, consts.PROXY_DATA_FILE,
            consts.VARIABLE_FILE, consts.APT_ARCHIVES_PATH,
            consts.INVENTORY_SOURCE_FOLDER, registry_port)
        if not ret_hosts:
            logger.error('FAILED IN DELTING NODE')
            exit(1)
        logger.info('EXECUTING CONFIGURE DOCKER REPO PLAY')
        ret_hosts = apbl.dynamic_docker_conf(
            consts.K8_DYNAMIC_DOCKER_CONF, ip, host_name, master_ip,
            consts.PROXY_DATA_FILE, consts.VARIABLE_FILE)
        if not ret_hosts:
            logger.error('FAILED IN CONFIGURE DOCKER REPO')
            exit(1)

    logger.info('EXECUTING DYNAMIC ADDITION OF NODE IN INVENTORY FILES PLAY')
    ret_hosts = modify_inventory_file(consts.KUBERNETES_NEW_INVENTORY,
                                      consts.KUBERNETES_CREATE_INVENTORY,
                                      dynamic_hostname_map,
                                      dynamic_host_node_type_map, project_name)
    if not ret_hosts:
        logger.error('FAILED DYNAMIC ADDITION OF NODE IN INVENTORY FILES')
        exit(1)

    for i in range(len(host_name_list)):
        host_name = host_name_list[i]
        logger.info('EXECUTING SET HOSTS PLAY')
        ret_hosts = apbl.dynamic_k8_nodes(
            consts.K8_DEPLOY_NODES, host_name,
            consts.INVENTORY_SOURCE_FOLDER,
            consts.VARIABLE_FILE, project_name)
        if not ret_hosts:
            logger.error('FAILED IN DEPLOY NODE IN K8')
            exit(1)
    time.sleep(5)
    # Node labeling start ##########
    if dynamic_hosts:
        for i in range(len(dynamic_hosts)):
            label_key = dynamic_hosts[i].get(consts.HOST).get(consts.LABEL_KEY)
            hostname = dynamic_hosts[i].get(consts.HOST).get(consts.HOSTNAME)
            label_value = dynamic_hosts[i].get(consts.HOST).get(
                consts.LABEL_VALUE)
            logger.info('EXECUTING LABEL NODE PLAY')
            ret_hosts = apbl.node_labeling(
                consts.K8_NODE_LABELING, master_hostname, hostname,
                label_key, label_value)
            if not ret_hosts:
                logger.error('FAILED IN LABEL NODE PLAY')
                exit(1)

                # Node labeling end ##########

    return ret_hosts


def launch_provisioning_kubernetes(host_name_map, host_node_type_map,
                                   host_port_map, service_subnet, pod_subnet,
                                   networking_plugin, enable_istio,
                                   docker_repo, hosts, git_branch,
                                   enable_ambassador, ambassador_rbac,
                                   project_name):
    """
    This function is used for deploy the kubernet cluster
    """
    proxy_data_file = consts.PROXY_DATA_FILE
    var_file = consts.VARIABLE_FILE
    apt_arch_path = consts.APT_ARCHIVES_PATH

    master_hostname = None
    for key, node_type in host_node_type_map.items():
        if node_type == "master":
            master_hostname = key
    for host_name, ip in host_name_map.items():
        registry_port = host_port_map.get(host_name)
        logger.info('EXECUTING SET HOSTS PLAY')
        ret_hosts = apbl.set_k8s_packages(
            consts.K8_SET_PACKAGES, ip, host_name, proxy_data_file,
            var_file, apt_arch_path, consts.INVENTORY_SOURCE_FOLDER,
            registry_port)
        if not ret_hosts:
            logger.error('FAILED SET HOSTS PLAY')
            exit(1)
    # Node configuration end ########

    # Docker Repository configuration start #######
    if docker_repo:
        docker_ip = docker_repo.get(consts.IP)
        docker_port = docker_repo.get(consts.PORT)
        logger.info('EXECUTING CREATING PRIVATE DOCKER REPO PLAY')
        ret_hosts = apbl.creating_docker_repo(
            consts.K8_PRIVATE_DOCKER, proxy_data_file, var_file,
            docker_ip, docker_port, apt_arch_path,
            consts.INVENTORY_SOURCE_FOLDER)
        if not ret_hosts:
            logger.error('FAILED IN  CREATING PRIVATE DOCKER REPO ')
            exit(1)
        for host_name, ip in host_name_map.items():
            logger.info('EXECUTING CONFIGURE DOCKER REPO PLAY')
            ret_hosts = apbl.docker_conf(
                consts.K8_CONF_DOCKER_REPO, ip, host_name, proxy_data_file,
                var_file, docker_ip, docker_port)
            if not ret_hosts:
                logger.error('FAILED IN CONFIGURE DOCKER REPO')
                exit(1)
                # Docker Repository configuration end
    logger.info('CREATING INVENTORY FILE PLAY')
    ret_hosts = apbl.create_inventory_file(
        consts.K8_CREATE_INVENTORY_FILE, consts.INVENTORY_SOURCE_FOLDER,
        var_file,
        consts.CWD, project_name)
    if not ret_hosts:
        logger.error('CREATING INVENTORY FILE')
        exit(1)
    logger.info('EXECUTING MODIFIY INVENTORY FILES PLAY')
    ret_hosts = modify_inventory_file(consts.KUBERNETES_NEW_INVENTORY,
                                      consts.KUBERNETES_CREATE_INVENTORY,
                                      host_name_map, host_node_type_map,
                                      project_name)
    if not ret_hosts:
        logger.error('FAILED TO MODIFIY INVENTORY FILES')
        exit(1)
    # Launcher configuration start
    logger.info('pip install --upgrade ansible==2.4.1.0')
    command = "pip install --upgrade ansible==2.4.1.0"
    res = subprocess.call(command, shell=True)
    if res != 0:
        logger.info('error in pip install --upgrade ansible==2.4.1.0')

    logger.info('EXECUTING SET HOSTS PLAY')
    ret_hosts = apbl.launch_k8s(
        consts.KUBERNETES_SET_LAUNCHER, service_subnet, pod_subnet,
        networking_plugin, proxy_data_file, var_file,
        consts.INVENTORY_SOURCE_FOLDER,
        consts.CWD, git_branch, project_name)
    if not ret_hosts:
        logger.error('FAILED IN SETTING LAUNCHER PACKAGES AND CONFIGURATION')
        exit(1)
    # Launcher configuration end

    # Node labeling start
    if hosts:
        for i in range(len(hosts)):
            host = hosts[i].get(consts.HOST)
            label_key = host.get(consts.LABEL_KEY)
            hostname = host.get(consts.HOSTNAME)
            label_value = host.get(consts.LABEL_VALUE)
            ret_hosts = apbl.node_labeling(
                consts.K8_NODE_LABELING, master_hostname, hostname,
                label_key, label_value)
            if not ret_hosts:
                logger.error('FAILED IN INSTALLING FILE PLAY')
                exit(1)

    for host_name, node_type in host_node_type_map.items():
        if node_type == "master":
            # Weave scope installation
            logger.info('EXECUTING WEAVE SCOPE PLAY')
            ret_hosts = apbl.weave_scope(
                consts.KUBERNETES_WEAVE_SCOPE, host_name,
                consts.INVENTORY_SOURCE_FOLDER,
                var_file)
            if not ret_hosts:
                logger.error('FAILED IN INSTALLING FILE PLAY')
                exit(1)

            logger.info('EXECUTING KUBE PROXY PLAY')
            ret_hosts = apbl.kube_proxy(
                consts.KUBERNETES_KUBE_PROXY, host_name,
                consts.INVENTORY_SOURCE_FOLDER,
                var_file)
            if not ret_hosts:
                logger.error('FAILED IN KUBE PROXY FILE PLAY')
                exit(1)
            else:
                logger.info('Started KUBE PROXY')
    if enable_istio == "yes":
        logger.info('SETUP ISTIO')
        ret_hosts = apbl.install_istio(
            consts.SETUP_ISTIO, consts.K8_INVENTORY_CFG,
            proxy_data_file)
        if not ret_hosts:
            logger.error('FAILED IN SETTING ISTIO')
            exit(1)
    if enable_ambassador == "yes":
        logger.info('SETUP AMBASSADOR')
        ret_hosts = apbl.install_ambassador(
            consts.SETUP_AMBASSADOR, consts.K8_INVENTORY_CFG,
            proxy_data_file, ambassador_rbac)
        if not ret_hosts:
            logger.error('FAILED IN SETTING AMBASSADOR')
            exit(1)

    logger.error('Completed launch_provisioning_kubernetes()')
    return ret_hosts


def modify_user_list(user_name, user_password, user_id):
    logger.info('EXECUTING SET Authentication HOSTS PLAY')
    ret_hosts = apbl.update_user_list(
        consts.KUBERNETES_USER_LIST, user_name, user_password, user_id,
        consts.INVENTORY_SOURCE_FOLDER)
    if not ret_hosts:
        logger.error('FAILED SET HOSTS PLAY')
        exit(1)
    return ret_hosts


def update_kube_api_manifest_file(master_host_name):
    logger.info('EXECUTING SET Authentication HOSTS PLAY')
    ret_hosts = apbl.launch_authentication(
        consts.KUBERNETES_AUTHENTICATION, master_host_name,
        consts.INVENTORY_SOURCE_FOLDER, consts.VARIABLE_FILE)
    if not ret_hosts:
        logger.error('FAILED SET HOSTS PLAY')
        exit(1)
    return ret_hosts


def modify_inventory_file(playbook1, playbook2, host_name_map,
                          host_node_type_map, project_name):
    for host_name, ip in host_name_map.items():
        logger.info('EXECUTING MODIFIED INVENTORY FILE PLAY')
        logger.info(playbook1)
        ret_hosts = apbl.launch_new_inventory(
            playbook1, ip, host_name, consts.INVENTORY_SOURCE_FOLDER,
            consts.VARIABLE_FILE,
            consts.CWD, project_name)
        if not ret_hosts:
            logger.error('FAILED IN MODIFIED INVENTORY FILE PLAY')
            exit(1)

    ret_hosts = False
    for host_name, node_type in host_node_type_map.items():
        logger.info('EXECUTING MODIFIED INVENTORY FILE PLAY')
        logger.info(playbook2)
        ret_hosts = apbl.launch_inventory(
            playbook2, node_type, host_name, consts.INVENTORY_SOURCE_FOLDER,
            consts.VARIABLE_FILE,
            project_name)
        if not ret_hosts:
            logger.error('FAILED IN MODIFIED INVENTORY FILE PLAY')
            exit(1)
    return ret_hosts


def launch_crd_network(host_name_map, host_node_type_map):
    """
    This function is used to create crd network
    """
    ret_hosts = False
    for host_name, node_type in host_node_type_map.items():
        logger.info('EXECUTING CRD NETWORK CREATION PLAY')
        for host_name1, ip in host_name_map.items():
            if node_type == "master" and host_name1 == host_name:
                ret_hosts = apbl.create_crd_network(
                    consts.K8_CREATE_CRD_NETWORK, ip, host_name,
                    consts.INVENTORY_SOURCE_FOLDER)
                if not ret_hosts:
                    logger.error('FAILED IN CREATING CRD NETWORK')
                    exit(1)
    return ret_hosts


def launch_multus_cni(host_name_map, host_node_type_map, networking_plugin):
    """
    This function is used to launch multus cni
    """
    ret_hosts = False
    logger.info('EXECUTING MULTUS CNI PLAY')
    for host_name, node_type in host_node_type_map.items():
        for host_name1, ip in host_name_map.items():
            if node_type == "master" and host_name1 == host_name:
                logger.info('EXECUTING MASTER MULTUS PLAY')
                ret_hosts = apbl.master_multus(
                    consts.K8_MULTUS_SET_MASTER, ip, host_name,
                    networking_plugin, consts.INVENTORY_SOURCE_FOLDER)
                if not ret_hosts:
                    logger.error('FAILED IN INSTALLING MULTUS AT MASTER')
                    exit(1)
            elif node_type == "minion" and host_name1 == host_name:
                logger.info('EXECUTING SCP MULTUS PLAY')
                ret_hosts = apbl.copy_multus(
                    consts.K8_MULTUS_SCP_MULTUS_CNI, ip, host_name,
                    networking_plugin, consts.INVENTORY_SOURCE_FOLDER)
                if not ret_hosts:
                    logger.error('FAILED IN SCP MULTUS AT NODE')
                    exit(1)
                logger.info('EXECUTING NODE MULTUS PLAY')
                ret_hosts = apbl.node_multus(
                    consts.K8_MULTUS_SET_NODE, ip, host_name,
                    networking_plugin, consts.INVENTORY_SOURCE_FOLDER)
                if not ret_hosts:
                    logger.error('FAILED IN INSTALLING MULTUS AT NODE')
                    exit(1)

    return ret_hosts


def launch_flannel_interface(host_name_map, host_node_type_map,
                             networking_plugin, item):
    """
    This function is used to launch flannel interface
    """
    logger.info('EXECUTING FLANNEL INTERFACE CREATION PLAY')
    network_dict = item.get("flannel_network")
    network = network_dict.get('network')
    subnet_len = network_dict.get('subnetLen')
    vni = network_dict.get('vni')
    master_ip = None
    ret_hosts = False

    for host_name, node_type in host_node_type_map.items():
        logger.info(consts.K8_CONF_FLANNEL_INTERFACE_AT_MASTER)
        for host_name1, ip in host_name_map.items():
            if node_type == "master" and host_name1 == host_name:
                master_ip = ip
                logger.info('EXECUTING FLANNEL INTF PLAY AT MASTER')
                ret_hosts = apbl.master_flannel(
                    consts.K8_CONF_FLANNEL_INTERFACE_AT_MASTER, ip, host_name,
                    networking_plugin, network, subnet_len, vni,
                    consts.INVENTORY_SOURCE_FOLDER)
                if not ret_hosts:
                    logger.error(
                        'FAILED IN CONFIGURING FLANNEL INTERFACE AT MASTER')
                    exit(1)

    for host_name, node_type in host_node_type_map.items():
        logger.info(consts.K8_CONF_FLANNEL_INTERFACE_AT_MASTER)
        for host_name1, ip in host_name_map.items():
            if node_type == "minion" and host_name1 == host_name:
                logger.info('EXECUTING FLANNEL INTF PLAY AT NODE')
                ret_hosts = apbl.node_flannel(
                    consts.K8_CONF_FLANNEL_INTERFACE_AT_NODE, ip, host_name,
                    networking_plugin, network, subnet_len, vni, master_ip,
                    consts.INVENTORY_SOURCE_FOLDER)
                if not ret_hosts:
                    logger.error(
                        'FAILED IN CONFIGURING FLANNEL INTERFACE AT NODE')
                    exit(1)

    return ret_hosts


def create_flannel_networks(host_name_map, host_node_type_map, item):
    """
    This function is used to create flannel networks
    """
    logger.info('CREATING FLANNEL NETWORK')
    network_dict = item.get("flannel_network")
    network_name = network_dict.get('network_name')
    vni = network_dict.get('vni')
    vni_int = int(vni)
    vni_temp1 = (vni_int - 1)
    vni_temp = str(vni_temp1)

    ret_hosts = False
    for host_name, node_type in host_node_type_map.items():
        for host_name1, ip in host_name_map.items():
            if node_type == "master" and host_name1 == host_name:
                logger.info('CREATING FLANNEL NETWORKS')
                ret_hosts = apbl.create_flannel_networks(
                    consts.K8_CONF_FLANNEL_NETWORK_CREATION, ip, host_name,
                    network_name, vni, vni_temp,
                    consts.INVENTORY_SOURCE_FOLDER)
                if not ret_hosts:
                    logger.error(
                        'FAILED IN CONFIGURING FLANNEL INTERFACE AT MASTER')
                    exit(1)
    return ret_hosts


def launch_sriov_cni_configuration(host_node_type_map, hosts_data_dict,
                                   project_name):
    """
    This function is used to launch sriov cni
    """
    k8_src_path = consts.K8_SOURCE_PATH
    minion_list = []
    logger.info('EXECUTING SRIOV CNI PLAY')
    logger.info("INSIDE launch_sriov_cni")
    dpdk_enable = "no"

    config = file_utils.read_yaml(consts.VARIABLE_FILE)
    project_path = config.get(consts.PROJECT_PATH)
    inventory_file_path = project_path + project_name + "/k8s-cluster.yml"
    logger.info('inventory file - %s', inventory_file_path)

    networking_plugin = None

    with open(inventory_file_path) as f:
        for line in f:
            if "kube_network_plugin:" in line:
                network_plugin1 = line.split("kube_network_plugin:", 1)[1]
                networking_plugin = network_plugin1.strip(' \t\n\r')
                logger.info('networking_plugin - %s', networking_plugin)

    dpdk_driver = None

    for node in hosts_data_dict:
        for key in node:
            if "Sriov" == key:
                all_hosts = node.get("Sriov")
                for hostData in all_hosts:
                    hostdetails = hostData.get("host")
                    hostname = hostdetails.get("hostname")
                    networks = hostdetails.get("networks")
                    minion_list.append(hostname)
                    for network in networks:
                        dpdk_driver = 'vfio-pci'
                        dpdk_enable = network.get("dpdk_enable")
                        sriov_intf = network.get("sriov_intf")
                        logger.info("SRIOV CONFIGURATION ON NODES")
                        ret_hosts = apbl.enable_sriov(
                            consts.K8_SRIOV_ENABLE, hostname,
                            sriov_intf,
                            consts.K8_SRIOV_CONFIG_SCRIPT,
                            networking_plugin)

    ret_hosts = apbl.build_sriov(
        consts.K8_SRIOV_CNI_BUILD, k8_src_path, consts.PROXY_DATA_FILE)
    logger.info("dpdk flag %s", dpdk_enable)
    if dpdk_enable == "yes":
        ret_hosts = apbl.build_sriov_dpdk(
            consts.K8_SRIOV_DPDK_CNI, k8_src_path, consts.PROXY_DATA_FILE)

    for host_name in get_master_host_name_list(host_node_type_map):
        logger.info("executing for master %s", host_name)
        logger.info("INSTALLING SRIOV BIN ON MASTER")
        ret_hosts = apbl.sriov_install(
            consts.K8_SRIOV_CNI_BIN_INST, host_name, k8_src_path)
        if dpdk_enable == "yes":
            logger.info("INSTALLING SRIOV DPDK BIN ON MASTER")
            ret_hosts = apbl.sriov_dpdk_install(
                consts.K8_SRIOV_DPDK_CNI_BIN_INST, host_name,
                k8_src_path)

    for host_name in minion_list:
        logger.info("executing for  minion %s", str(host_name))
        logger.info("INSTALLING SRIOV BIN ON WORKERS")
        ret_hosts = apbl.sriov_install(
            consts.K8_SRIOV_CNI_BIN_INST, host_name, k8_src_path)
        if dpdk_enable == "yes":
            logger.info("INSTALLING SRIOV DPDK BIN ON WORKERS")
            ret_hosts = apbl.dpdk_driver_load(
                consts.K8_SRIOV_DPDK_DRIVER_LOAD, host_name, dpdk_driver)
            ret_hosts = apbl.sriov_dpdk_install(
                consts.K8_SRIOV_DPDK_CNI_BIN_INST, host_name,
                k8_src_path)

    return ret_hosts


def launch_sriov_network_creation(hosts_data_dict, project_name):
    ret_hosts = False
    playbook_path_sriov_conf = consts.K8_SRIOV_CONF
    master_host = get_host_master_name(project_name)
    logger.info("Performing config for node - %s", master_host)
    for node in hosts_data_dict:
        for key in node:
            if "Sriov" == key:
                all_hosts = node.get("Sriov")
                for host_data in all_hosts:
                    host_details = host_data.get("host")
                    networks = host_details.get("networks")
                    node_hostname = host_details.get("hostname")
                    for network in networks:
                        dpdk_tool = '/etc/cni/scripts/dpdk-devbind.py'
                        dpdk_driver = 'vfio-pci'
                        dpdk_enable = network.get("dpdk_enable")
                        range_end = network.get("rangeEnd")
                        range_start = network.get("rangeStart")
                        host = network.get("type")
                        sriov_gateway = network.get("sriov_gateway")
                        sriov_intf = network.get("sriov_intf")
                        sriov_subnet = network.get("sriov_subnet")
                        sriov_nw_name = network.get("network_name")
                        if dpdk_enable == "yes":
                            logger.info(
                                'SRIOV NETWORK CREATION STARTED USING DPDK '
                                'DRIVER')
                            ret_hosts = apbl.sriov_dpdk_crd_nw(
                                consts.K8_SRIOV_DPDK_CR_NW,
                                playbook_path_sriov_conf, sriov_intf,
                                master_host, sriov_nw_name, dpdk_driver,
                                dpdk_tool, node_hostname)
                        if dpdk_enable == "no":
                            if host == "host-local":
                                logger.info(
                                    'SRIOV NETWORK CREATION STARTED USING '
                                    'KERNEL DRIVER WITH IPAM host-local')
                                ret_hosts = apbl.sriov_crd_nw(
                                    consts.K8_SRIOV_CR_NW,
                                    playbook_path_sriov_conf, sriov_intf,
                                    master_host, sriov_nw_name, range_start,
                                    range_end, sriov_subnet, sriov_gateway)

                            if host == "dhcp":
                                logger.info(
                                    'SRIOV NETWORK CREATION STARTED USING '
                                    'KERNEL DRIVER WITH IPAM host-dhcp')
                                ret_hosts = apbl.sriov_dhcp_crd_nw(
                                    consts.K8_SRIOV_DHCP_CR_NW,
                                    playbook_path_sriov_conf, sriov_intf,
                                    master_host, sriov_nw_name)
    return ret_hosts


def get_master_host_name_list(host_node_type_map):
    master_list = []
    for key, value in host_node_type_map.items():
        if value == "master":
            master_list.append(key)
    return master_list


def create_weave_interface(host_name_map, host_node_type_map,
                           networking_plugin, item):
    """
    This function is used to create weave interace and network
    """
    ret_hosts = False
    logger.info('CREATING WEAVE NETWORK')
    network_dict = item.get("weave_network")
    network_name = network_dict.get('network_name')
    subnet = network_dict.get('subnet')

    for host_name, node_type in host_node_type_map.items():
        for host_name1, ip in host_name_map.items():
            if node_type == "master" and host_name1 == host_name:
                logger.info('CREATING WEAVE NETWORKS')
                ret_hosts = apbl.create_weave_network(
                    consts.K8_CONF_WEAVE_NETWORK_CREATION, ip, host_name,
                    network_name, subnet, consts.INVENTORY_SOURCE_FOLDER)
                if not ret_hosts:
                    logger.error('FAILED IN CONFIGURING WEAVE INTERFACE')
                    exit(1)

    for host_name, node_type in host_node_type_map.items():
        for host_name1, ip in host_name_map.items():
            if node_type == "minion" and host_name1 == host_name:
                logger.info('DELETING CONF FILE')
                ret_hosts = apbl.delete_weave_conf(
                    consts.K8_CONF_FILES_DELETION_AFTER_MULTUS, ip, host_name,
                    networking_plugin, consts.INVENTORY_SOURCE_FOLDER)
                if not ret_hosts:
                    logger.error('FAILED IN CONFIGURING WEAVE INTERFACE')
                    exit(1)
    return ret_hosts


def __hostname_list(hosts):
    logger.info("Creating host name list")
    out_list = []
    for i in range(len(hosts)):
        name = hosts[i].get(consts.HOST).get(consts.HOSTNAME)
        if name:
            host_name = name
            out_list.append(host_name)
    return out_list


def launch_metrics_server(hostname_map, host_node_type_map):
    return_stmnt = False
    logger.info("launch_metrics_server fucntion")
    for host_name, node_type in host_node_type_map.items():
        if node_type == "master":
            logger.info(
                'CONFIGURING METRICS SERVER on - %s -> %s ip -> %s',
                node_type, host_name, str(hostname_map[host_name]))
            return_stmnt = apbl.metrics_server(
                consts.K8_METRRICS_SERVER, hostname_map[host_name],
                host_name, consts.PROXY_DATA_FILE)

    return return_stmnt


def clean_up_metrics_server(hostname_map, host_node_type_map):
    logger.info("clean_up_metrics_server")
    return_stmnt = False
    for host_name, node_type in host_node_type_map.items():
        if node_type == "master":
            logger.info(
                'REMOVING METRICS SERVER on - %s -> %s ip -> %s',
                node_type, host_name, str(hostname_map[host_name]))
            return_stmnt = apbl.metrics_server_clean(
                consts.K8_METRRICS_SERVER_CLEAN, hostname_map[host_name],
                host_name)

    return return_stmnt


def launch_ceph_kubernetes(host_node_type_map, hosts, ceph_hosts):
    """
    This function is used for deploy the ceph
    """
    ret_hosts = False
    proxy_data_file = consts.PROXY_DATA_FILE
    var_file = consts.VARIABLE_FILE
    master_hostname = None
    for key, node_type1 in host_node_type_map.items():
        if node_type1 == "master":
            master_hostname = key
    if hosts:
        for i in range(len(hosts)):
            node_type = hosts[i].get(consts.HOST).get(consts.NODE_TYPE)
            logger.info(node_type)
            if node_type == "master":
                ret_hosts = apbl.delete_secret(
                    consts.KUBERNETES_CEPH_DELETE_SECRET, master_hostname)
                if not ret_hosts:
                    logger.error('FAILED IN INSTALLING FILE PLAY')
                    exit(1)

    controller_host_name = None
    ceph_controller_ip = None

    if ceph_hosts:
        ceph_hostnamelist = __hostname_list(ceph_hosts)
        for i in range(len(ceph_hosts)):
            host_ip = ceph_hosts[i].get(consts.HOST).get(consts.IP)
            host_name = ceph_hosts[i].get(consts.HOST).get(consts.HOSTNAME)
            node_type = ceph_hosts[i].get(consts.HOST).get(consts.NODE_TYPE)
            ret_hosts = apbl.ceph_volume_first(
                consts.KUBERNETES_CEPH_VOL_FIRST, host_name,
                consts.INVENTORY_SOURCE_FOLDER,
                var_file, proxy_data_file, host_ip)
            if not ret_hosts:
                logger.error('FAILED IN INSTALLING FILE PLAY')
                exit(1)
            if node_type == "ceph_controller":
                ceph_controller_ip = ceph_hosts[i].get(consts.HOST).get(
                    consts.IP)
                logger.info('EXECUTING CEPH VOLUME PLAY')
                controller_host_name = host_name

                # TODO/FIXME - Why is the var 'i' being used in the inner and outer loops?
                for i in range(len(ceph_hostnamelist)):
                    osd_host_name = ceph_hostnamelist[i]
                    user_id = ceph_hosts[i].get(consts.HOST).get(consts.USER)
                    passwd = ceph_hosts[i].get(consts.HOST).get(
                        consts.PASSWORD)
                    osd_ip = ceph_hosts[i].get(consts.HOST).get(consts.IP)
                    ret_hosts = apbl.ceph_volume(
                        consts.KUBERNETES_CEPH_VOL, host_name,
                        consts.INVENTORY_SOURCE_FOLDER,
                        var_file, proxy_data_file, osd_host_name, user_id,
                        passwd, osd_ip)
                if not ret_hosts:
                    logger.error('FAILED IN INSTALLING FILE PLAY')
                    exit(1)
        for i in range(len(ceph_hostnamelist)):
            host_name = ceph_hostnamelist[i]
            user_id = ceph_hosts[i].get(consts.HOST).get(consts.USER)
            passwd = ceph_hosts[i].get(consts.HOST).get(consts.PASSWORD)
            ret_hosts = apbl.ceph_deploy(
                consts.CEPH_DEPLOY, host_name, controller_host_name,
                var_file, proxy_data_file, user_id, passwd)
            if not ret_hosts:
                logger.error('FAILED IN INSTALLING FILE PLAY')
                exit(1)
        ret_hosts = apbl.ceph_mon(
            consts.CEPH_MON, controller_host_name, var_file,
            proxy_data_file)
        if not ret_hosts:
            logger.error('FAILED IN INSTALLING FILE PLAY')
            exit(1)
        for i in range(len(ceph_hosts)):
            host_name = ceph_hosts[i].get(consts.HOST).get(consts.HOSTNAME)
            node_type = ceph_hosts[i].get(consts.HOST).get(consts.NODE_TYPE)
            flag_second_storage = 0
            if node_type == "ceph_osd":
                flag_second_storage = 1
                second_storage = ceph_hosts[i].get(consts.HOST).get(
                    consts.STORAGE_TYPE)
                logger.info("secondstorage is")
                if second_storage:
                    # TODO/FIXME - Why is the var 'i' being used by the inner and outer loops?
                    for i in range(len(second_storage)):
                        storage = second_storage[i]
                        logger.info('EXECUTING CEPH STORAGE PLAY')
                        ret_hosts = apbl.ceph_storage(
                            consts.KUBERNETES_CEPH_STORAGE, host_name,
                            controller_host_name,
                            consts.INVENTORY_SOURCE_FOLDER,
                            var_file, storage, proxy_data_file, node_type)
                        if not ret_hosts:
                            logger.error('FAILED IN INSTALLING FILE PLAY')
                            exit(1)
        for i in range(len(ceph_hostnamelist)):
            host_name = ceph_hostnamelist[i]
            ret_hosts = apbl.ceph_deploy_admin(
                consts.CEPH_DEPLOY_ADMIN, host_name,
                controller_host_name, var_file, proxy_data_file)
            if not ret_hosts:
                logger.error('FAILED IN INSTALLING FILE PLAY')
                exit(1)
        ret_hosts = apbl.ceph_mon(
            consts.CEPH_MDS, controller_host_name, var_file,
            proxy_data_file)
        if not ret_hosts:
            logger.error('FAILED IN INSTALLING FILE PLAY')
            exit(1)
    if hosts:
        for i in range(len(hosts)):
            host = hosts[i].get(consts.HOST)
            node_type = host.get(consts.NODE_TYPE)
            logger.info(node_type)
            if node_type == "master":
                hostname = host.get(consts.HOSTNAME)
                logger.info("flag secondstorage is")
                logger.info(flag_second_storage)
                if 1 == flag_second_storage:
                    ceph_claims = ceph_hosts[i].get(consts.HOST).get(
                        consts.CEPH_CLAIMS)
                    # TODO/FIXME - Why is the var 'i' being used in the inner and outer loops?
                    for i in range(len(ceph_claims)):
                        ceph_claim_name = ceph_claims[i].get(
                            consts.CLAIM_PARAMETERS).get(
                            consts.CEPH_CLAIM_NAME)
                        logger.info("ceph claim name - %s", ceph_claim_name)
                        ceph_storage_size = ceph_claims[i].get(
                            consts.CLAIM_PARAMETERS).get(consts.CEPH_STORAGE)
                        logger.info("ceph storage size - %s",
                                    ceph_storage_size)
                        ret_hosts = apbl.ceph_volume2(
                            consts.KUBERNETES_CEPH_VOL2, hostname,
                            consts.INVENTORY_SOURCE_FOLDER, var_file,
                            ceph_storage_size,
                            ceph_claim_name, proxy_data_file,
                            controller_host_name, ceph_controller_ip)
                        if not ret_hosts:
                            logger.error('FAILED IN INSTALLING FILE PLAY')
                            exit(1)
    return ret_hosts


def launch_persitent_volume_kubernetes(host_node_type_map, persistent_vol):
    """
 This function is used for deploy the persistent_volume
 """
    ret_hosts = False
    for host_name, node_type in host_node_type_map.items():
        if node_type == "master":
            for i in range(len(persistent_vol)):
                storage_size = persistent_vol[i].get(
                    consts.CLAIM_PARAMETERS).get(consts.STORAGE)
                claim_name = persistent_vol[i].get(
                    consts.CLAIM_PARAMETERS).get(consts.CLAIM_NAME)
                logger.info('EXECUTING PERSISTENT VOLUME PLAY')
                ret_hosts = apbl.persistent_volume(
                    consts.KUBERNETES_PERSISTENT_VOL, host_name,
                    consts.INVENTORY_SOURCE_FOLDER, consts.VARIABLE_FILE,
                    storage_size, claim_name)
                if not ret_hosts:
                    logger.error('FAILED IN INSTALLING FILE PLAY')
                    exit(1)
    return ret_hosts


def get_host_master_name(project_name):
    config = file_utils.read_yaml(consts.VARIABLE_FILE)
    project_path = config.get(consts.PROJECT_PATH)
    inventory_file_path = project_path + project_name + "/inventory.cfg"
    logger.info("Inventory file path - %s", inventory_file_path)
    master_hostname = None
    with open(inventory_file_path) as f:
        for line in f:
            if re.match("\[kube-master\]", line):
                master_hostname1 = f.next()
                master_hostname = master_hostname1.strip(' \t\n\r')
                logger.info("master host name - %s", master_hostname)
    return master_hostname


def get_hostname_ip_map_list(project_name):
    config = file_utils.read_yaml(consts.VARIABLE_FILE)
    project_path = config.get(consts.PROJECT_PATH)
    inventory_file_path = project_path + project_name + "/inventory.cfg"
    logger.info("Inventory file path - %s", inventory_file_path)
    hostname_map = {}
    with open(inventory_file_path) as f:
        for line in f:
            if "ansible_ssh_host=" in line:
                host_ip1 = line.split("ansible_ssh_host=", 1)[1]
                host_ip = host_ip1.strip(' \t\n\r')
                host_name = line.split(" ")[0]
                host_name = host_name.strip(' \t\n\r')
                if host_ip:
                    if host_name:
                        hostname_map[host_name] = host_ip
    return hostname_map


def launch_multus_cni_dynamic_node(dynamic_hostname_map, master_ip,
                                   project_name):
    """
    This function is used to launch multus cni on dynamic node
    """
    ret_hosts = False
    logger.info('EXECUTING MULTUS CNI PLAY ON DYNAMIC NODE')
    config = file_utils.read_yaml(consts.VARIABLE_FILE)
    project_path = config.get(consts.PROJECT_PATH)
    inventory_file_path = project_path + project_name + "/k8s-cluster.yml"
    logger.info("Inventory file path - %s", inventory_file_path)

    networking_plugin = None

    with open(inventory_file_path) as f:
        for line in f:
            if "kube_network_plugin:" in line:
                network_plugin1 = line.split("kube_network_plugin:", 1)[1]
                networking_plugin = network_plugin1.strip(' \t\n\r')
                logger.info("networking plugin - %s", networking_plugin)

    for host_name, ip in dynamic_hostname_map.items():
        logger.info('EXECUTING SCP MULTUS PLAY ON DYNAMIC NODE')
        ret_hosts = apbl.copy_multus_dynamic_node(
            consts.K8_MULTUS_SCP_MULTUS_CNI_DYNAMIC_NODE, ip, host_name,
            master_ip,
            consts.INVENTORY_SOURCE_FOLDER)
        if not ret_hosts:
            logger.error('FAILED IN SCP MULTUS AT NODE ON DYNAMIC NODE')
            exit(1)
        logger.info('EXECUTING NODE MULTUS PLAY ON DYNAMIC NODE')
        ret_hosts = apbl.dynamic_node_multus(
            consts.K8_MULTUS_SET_DYNAMIC_NODE, ip, host_name,
            networking_plugin, consts.INVENTORY_SOURCE_FOLDER)
        if not ret_hosts:
            logger.error('FAILED IN INSTALLING MULTUS ON DYNAMIC NODE')
            exit(1)

    return ret_hosts


def launch_flannel_interface_dynamic_node(dynamic_hostname_map, item,
                                          master_ip, project_name):
    """
 This function is used to launch flannel interface
 """
    master_hostname = get_host_master_name(project_name)
    logger.info('EXECUTING FLANNEL INTERFACE CREATION PLAY AT DYNAMIC NODE')
    network_dict = item.get("flannel_network")
    network = network_dict.get('network')
    subnet_len = network_dict.get('subnetLen')
    vni = network_dict.get('vni')

    logger.info('EXECUTING FLANNEL INTF PLAY AT MASTER_DYNAMIC_NODE')
    ret_hosts = apbl.master_flannel_dynamic_node(
        consts.K8_CONF_FLANNEL_INTERFACE_AT_MASTER_FOR_DYNAMIC_NODE, master_ip,
        master_hostname, network, subnet_len, vni,
        consts.INVENTORY_SOURCE_FOLDER)
    if not ret_hosts:
        logger.error(
            'FAILED IN CONFIGURING FLANNEL INTERFACE AT MASTER FOR DYNAMIC '
            'NODE')
        exit(1)

    for host_name, ip in dynamic_hostname_map.items():
        logger.info('EXECUTING FLANNEL INTF PLAY AT DYNAMIC NODE')
        ret_hosts = apbl.dynamic_node_flannel(
            consts.K8_CONF_FLANNEL_INTERFACE_AT_DYNAMIC_NODE, ip, host_name,
            network, subnet_len, vni, master_ip,
            consts.INVENTORY_SOURCE_FOLDER)
        if not ret_hosts:
            logger.error(
                'FAILED IN CONFIGURING FLANNEL INTERFACE AT DYNAMIC NODE')
            exit(1)

    return ret_hosts


def delete_existing_conf_files(dynamic_hostname_map, project_name):
    """
    This function is used to delete existing conf files
    """
    ret_hosts = False
    logger.info('DELETING EXISTING CONF FILES')
    config = file_utils.read_yaml(consts.VARIABLE_FILE)
    project_path = config.get(consts.PROJECT_PATH)
    inventory_file_path = project_path + project_name + "/k8s-cluster.yml"
    logger.info('inventory file path: %s', inventory_file_path)
    networking_plugin = None
    with open(inventory_file_path) as f:
        for line in f:
            if "kube_network_plugin:" in line:
                network_plugin1 = line.split("kube_network_plugin:", 1)[1]
                networking_plugin = network_plugin1.strip(' \t\n\r')
                logger.info("networking plugin - %s", networking_plugin)
    for host_name, ip in dynamic_hostname_map.items():
        logger.info('EXECUTING DELETE CONF FILES PLAY ON DYNAMIC NODE')
        ret_hosts = apbl.delete_conf_files(
            consts.K8_CONF_FILES_DELETION_AFTER_MULTUS, ip, host_name,
            networking_plugin, consts.INVENTORY_SOURCE_FOLDER)
        if not ret_hosts:
            logger.error('FAILED IN DELETING CONF FILES ON DYNAMIC NODE')
            exit(1)

    return ret_hosts


def delete_existing_conf_files_after_additional_plugins(host_name_map,
                                                        host_node_type_map,
                                                        networking_plugin):
    """
    This function is used to delete existing conf files
    """
    ret_hosts = False
    logger.info('DELETING EXISTING CONF FILES AFTER MULTUS')
    for host_name, node_type in host_node_type_map.items():
        for host_name1, ip in host_name_map.items():
            if node_type == "minion" and host_name1 == host_name:
                logger.info('EXECUTING DELETE CONF FILES PLAY')
                ret_hosts = apbl.delete_conf_files(
                    consts.K8_CONF_FILES_DELETION_AFTER_MULTUS,
                    ip, host_name, networking_plugin,
                    consts.INVENTORY_SOURCE_FOLDER)
                if not ret_hosts:
                    logger.error('FAILED IN DELETING CONF FILES')
                    exit(1)

    return ret_hosts


def delete_flannel_interfaces(host_name_map, host_node_type_map,
                              hosts_data_dict, project_name):
    """
    This function is used to delete flannel interfaces
    """
    ret_hosts = False
    playbook_path_conf_delete_flannel_intf = consts.K8_DELETE_FLANNEL_INTERFACE
    logger.info('EXECUTING FLANNEL INTERFACE DELETION PLAY')
    network_name = None
    for item1 in hosts_data_dict:
        for key1 in item1:
            if key1 == "Multus_network":
                multus_network = item1.get("Multus_network")
                for item2 in multus_network:
                    for key2 in item2:
                        if key2 == "CNI_Configuration":
                            cni_configuration = item2.get("CNI_Configuration")
                            for item3 in cni_configuration:
                                for key3 in item3:
                                    if consts.FLANNEL_NETWORK == key3:
                                        all_hosts = item3.get(
                                            consts.FLANNEL_NETWORK)
                                        for hostData in all_hosts:
                                            hostdetails = hostData.get(
                                                "flannel_network")
                                            network_name = hostdetails.get(
                                                "network_name")

    logger.info("networkName: %s", network_name)
    hostname_master = None
    hostname_minion = None
    node_type_minion = None

    for host_name, node_type in host_node_type_map.items():
        logger.info(playbook_path_conf_delete_flannel_intf)
        for host_name1, ip in host_name_map.items():
            if node_type == "master" and host_name1 == host_name:
                hostname_master = host_name1
                ret_hosts = apbl.delete_flannel_interfaces(
                    playbook_path_conf_delete_flannel_intf, ip, host_name,
                    node_type, network_name, consts.INVENTORY_SOURCE_FOLDER)
                if not ret_hosts:
                    logger.error('FAILED IN DELETING FLANNEL INTERFACE')
                    exit(1)
            if node_type == "minion" and host_name1 == host_name:
                hostname_minion = host_name1
                node_type_minion = node_type
                logger.info("node_type: %s", node_type)
                ret_hosts = apbl.delete_flannel_interfaces(
                    playbook_path_conf_delete_flannel_intf, ip, host_name,
                    node_type, network_name, consts.INVENTORY_SOURCE_FOLDER)
                if not ret_hosts:
                    logger.error('FAILED IN DELETING FLANNEL INTERFACE')
                    exit(1)

    host_name_map_ip = get_hostname_ip_map_list(project_name)
    for host_name, ip in host_name_map_ip.items():
        if hostname_master != host_name and hostname_minion != host_name:
            logger.info("dynamic node ip: %s", ip)
            logger.info("dynamic host name: %s", host_name)
            node_type = node_type_minion
            ret_hosts = apbl.delete_flannel_interfaces(
                playbook_path_conf_delete_flannel_intf, ip, host_name,
                node_type, network_name, consts.INVENTORY_SOURCE_FOLDER)
            if not ret_hosts:
                logger.error('FAILED IN DELETING FLANNEL INTERFACE')
                exit(1)

    return ret_hosts


"""****** end kubernetes fucntions *****************"""


def create_default_network(host_name_map, host_node_type_map,
                           networking_plugin, item):
    """
    This function is create default network
    """
    ret_hosts = False
    logger.info('EXECUTING CREATE DEFAULT NETWORK PLAY')

    subnet = item.get('pod_subnet')
    network_name = item.get('network_name')
    for host_name, node_type in host_node_type_map.items():
        for host_name1, ip in host_name_map.items():
            if node_type == "master" and host_name1 == host_name:
                ret_hosts = apbl.create_default_network(
                    consts.K8_CREATE_DEFAULT_NETWORK, ip, host_name,
                    network_name, subnet, networking_plugin,
                    consts.INVENTORY_SOURCE_FOLDER)
                if not ret_hosts:
                    logger.info('FAILED IN CREATING DEFAULT NETWORK')

    return ret_hosts


def create_flannel_interface(host_name_map, host_node_type_map,
                             project_name, hosts_data_dict):
    ret_hosts = False
    logger.info('EXECUTING FLANNEL INTERFACE CREATION PLAY IN CREATE FUNC')
    master_list = get_master_host_name_list(host_node_type_map)
    logger.info('master_list - %s', str(master_list))
    master_host = get_host_master_name(project_name)
    logger.info('Doing config for node - %s', str(master_host))

    master_host_name = None

    for host_name, node_type in host_node_type_map.items():
        for host_name1, ip in host_name_map.items():
            if node_type == "master" and host_name1 == host_name:
                master_ip = ip
                master_host_name = host_name

    network = None
    network_name = None
    for item1 in hosts_data_dict:
        for key1 in item1:
            if key1 == "Multus_network":
                multus_network = item1.get("Multus_network")
                for item2 in multus_network:
                    for key2 in item2:
                        if key2 == "CNI_Configuration":
                            logger.info('CNI key: %s', key2)
                            cni_configuration = item2.get("CNI_Configuration")
                            for item3 in cni_configuration:
                                for key3 in item3:
                                    logger.info('Network key: %s', key3)
                                    logger.info(
                                        "consts.FLANNEL_NETWORK value is %s",
                                        consts.FLANNEL_NETWORK)
                                    if consts.FLANNEL_NETWORK == key3:
                                        all_hosts = item3.get(
                                            consts.FLANNEL_NETWORK)
                                        for host_data in all_hosts:
                                            host_details = host_data.get(
                                                "flannel_network")
                                            network_name = host_details.get(
                                                "network_name")
                                            network = host_details.get(
                                                "network")
                                            cidr = host_details.get("subnet")
                                            logger.info(
                                                'Calling flannel daemon')
                                            logger.info(
                                                'Calling %s with IP - %s, network - %s, cidr - %s',
                                                consts.K8_CONF_FLANNEL_INTF_CREATION_AT_MASTER,
                                                master_ip, network, cidr)
                                            ret_hosts = apbl.flannel_daemon(
                                                consts.K8_CONF_FLANNEL_DAEMON_AT_MASTER,
                                                master_ip, network, cidr,
                                                consts.INVENTORY_SOURCE_FOLDER)
                                            if not ret_hosts:
                                                ret_hosts = False
                                                logger.info(
                                                    'FAILED IN CREATING '
                                                    'FLANNEL NETWORK')
                                            else:
                                                ret_hosts = True
    logger.info("networkName: %s", network_name)

    if ret_hosts:
        time.sleep(30)
        ret_hosts = apbl.create_flannel_interface(
            consts.K8_CONF_FLANNEL_INTF_CREATION_AT_MASTER, master_ip,
            master_host_name, network_name, network,
            consts.INVENTORY_SOURCE_FOLDER)
        if not ret_hosts:
            ret_hosts = False
            logger.info('FAILED IN CREATING FLANNEL NETWORK')

    return ret_hosts


def clean_up_flannel_dynamic_node(dynamic_hostname_map):
    """
    This function is used to delete flannel interface at dynamic node
    """
    ret_hosts = False
    logger.info('EXECUTING FLANNEL INTERFACE DELETION PLAY AT DYNAMIC NODE')
    for host_name, ip in dynamic_hostname_map.items():
        logger.info(consts.K8_DELETE_FLANNEL_INTERFACE_DYNAMIC_NODE)
        ret_hosts = apbl.dynamic_node_flannel_clean_up(
            consts.K8_DELETE_FLANNEL_INTERFACE_DYNAMIC_NODE, ip, host_name,
            consts.INVENTORY_SOURCE_FOLDER)
        if not ret_hosts:
            logger.info('FAILED IN DELETING FLANNEL INTERFACE AT DYNAMIC NODE')

    return ret_hosts


def delete_weave_interface(host_name_map, host_node_type_map, hosts_data_dict,
                           project_name):
    """
    This function is used to delete weave interface
    """
    ret_hosts = False
    logger.info('EXECUTING WEAVE INTERFACE DELETION PLAY')
    network_name = None
    for item1 in hosts_data_dict:
        for key1 in item1:
            if key1 == "Multus_network":
                multus_network = item1.get("Multus_network")
                for item2 in multus_network:
                    for key2 in item2:
                        if key2 == "CNI_Configuration":
                            cni_configuration = item2.get("CNI_Configuration")
                            for item3 in cni_configuration:
                                for key3 in item3:
                                    if consts.WEAVE_NETWORK == key3:
                                        weave_network = item3.get(
                                            consts.WEAVE_NETWORK)
                                        for weave_item in weave_network:
                                            network_name = weave_item.get(
                                                "network_name")

    logger.info("networkName: %s", network_name)

    hostname_master = None
    hostname_minion = None
    node_type_minion = None
    for host_name, node_type in host_node_type_map.items():
        for host_name1, ip in host_name_map.items():
            if node_type == "master" and host_name1 == host_name:
                hostname_master = host_name1
                ret_hosts = apbl.delete_weave_interface(
                    consts.K8_DELETE_WEAVE_INTERFACE, ip, host_name,
                    node_type, network_name, consts.INVENTORY_SOURCE_FOLDER)
                if not ret_hosts:
                    logger.info('FAILED IN DELETING WEAVE INTERFACE')
            if node_type == "minion" and host_name1 == host_name:
                hostname_minion = host_name1
                node_type_minion = node_type
                logger.info("node_type: %s", node_type)
                ret_hosts = apbl.delete_weave_interface(
                    consts.K8_DELETE_WEAVE_INTERFACE, ip, host_name,
                    node_type, network_name, consts.INVENTORY_SOURCE_FOLDER)
                if not ret_hosts:
                    logger.info('FAILED IN DELETING WEAVE INTERFACE')

    host_name_map_ip = get_hostname_ip_map_list(project_name)
    for host_name, ip in host_name_map_ip.items():
        if hostname_master != host_name and hostname_minion != host_name:
            logger.info("dynamic node ip: %s", ip)
            logger.info("dynamic host name: %s", host_name)
            node_type = node_type_minion
            ret_hosts = apbl.delete_weave_interface(
                consts.K8_DELETE_WEAVE_INTERFACE, ip, host_name, node_type,
                network_name, consts.INVENTORY_SOURCE_FOLDER)
            if not ret_hosts:
                logger.info('FAILED IN DELETING WEAVE INTERFACE')

    return ret_hosts


def clean_up_weave_dynamic_node(dynamic_hostname_map):
    """
    This function is used to delete weave interface at dynamic node
    """
    ret_hosts = False
    logger.info('EXECUTING WEAVE INTERFACE DELETION PLAY AT DYNAMIC NODE')
    for host_name, ip in dynamic_hostname_map.items():
        logger.info(consts.K8_DELETE_WEAVE_INTERFACE_DYNAMIC_NODE)
        ret_hosts = apbl.dynamic_node_weave_clean_up(
            consts.K8_DELETE_WEAVE_INTERFACE_DYNAMIC_NODE, ip, host_name,
            consts.INVENTORY_SOURCE_FOLDER)
        if not ret_hosts:
            logger.info('FAILED IN DELETING WEAVE INTERFACE AT DYNAMIC NODE')

    return ret_hosts


def delete_default_weave_interface(host_name_map, host_node_type_map,
                                   hosts_data_dict, project_name):
    """
    This function is used to delete default weave interface
    """
    ret_hosts = False
    logger.info('EXECUTING WEAVE INTERFACE DELETION PLAY')
    network_name = None
    networking_plugin = None
    for item1 in hosts_data_dict:
        for key in item1:
            if key == "Default_Network":
                default_network = item1.get("Default_Network")
                if default_network:
                    networking_plugin = default_network.get(
                        consts.NETWORKING_PLUGIN)
                    network_name = default_network.get(consts.NETWORK_NAME)

    logger.info("networkName: %s", network_name)

    if networking_plugin != "weave":
        logger.info(
            'DEFAULT NETWORKING PLUGIN IS NOT WEAVE, NO NEED TO CLEAN WEAVE')
        ret_hosts = True
        return ret_hosts

    hostname_master = None
    hostname_minion = None
    node_type_minion = None

    for host_name, node_type in host_node_type_map.items():
        logger.info(consts.K8_DELETE_WEAVE_INTERFACE)
        for host_name1, ip in host_name_map.items():
            if node_type == "master" and host_name1 == host_name:
                hostname_master = host_name1
                ret_hosts = apbl.delete_weave_interface(
                    consts.K8_DELETE_WEAVE_INTERFACE, ip, host_name,
                    node_type, network_name, consts.INVENTORY_SOURCE_FOLDER)
                if not ret_hosts:
                    logger.info('FAILED IN DELETING WEAVE INTERFACE')
            if node_type == "minion" and host_name1 == host_name:
                hostname_minion = host_name1
                node_type_minion = node_type
                logger.info("node_type: %s", node_type)
                ret_hosts = apbl.delete_weave_interface(
                    consts.K8_DELETE_WEAVE_INTERFACE, ip, host_name,
                    node_type, network_name, consts.INVENTORY_SOURCE_FOLDER)
                if not ret_hosts:
                    logger.info('FAILED IN DELETING WEAVE INTERFACE')

    host_name_map_ip = get_hostname_ip_map_list(project_name)
    for host_name, ip in host_name_map_ip.items():
        if hostname_master != host_name and hostname_minion != host_name:
            logger.info("dynamic node ip: %s", ip)
            logger.info("dynamic host name: %s", host_name)
            node_type = node_type_minion
            ret_hosts = apbl.delete_weave_interface(
                consts.K8_DELETE_WEAVE_INTERFACE, ip, host_name, node_type,
                network_name, consts.INVENTORY_SOURCE_FOLDER)
            if not ret_hosts:
                logger.info('FAILED IN DELETING WEAVE INTERFACE')

    return ret_hosts

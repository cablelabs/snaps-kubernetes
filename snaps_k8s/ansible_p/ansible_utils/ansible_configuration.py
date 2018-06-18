###########################################################################
# Copyright 2018 ARICENT HOLDINGS LUXEMBOURG SARL. and
# Cable Television Laboratories, Inc.
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
###########################################################################


import re
import logging
import time
import subprocess
from snaps_k8s.ansible_p.ansible_utils.ansible_playbook_launcher import KubectlPlayBookLauncher
from snaps_k8s.ansible_p.ansible_utils.ansible_playbook_launcher import CleanUpMultusPlayBookLauncher
from snaps_k8s.common.consts import consts
from snaps_k8s.common.utils import file_utils
import ansible_playbook_launcher as apbl

DEFAULT_REPLACE_EXTENSIONS = None

logger = logging.getLogger('deploy_ansible_configuration')

def provision_preparation(proxy_dict, dpdk):
    """
    This method is responsible for writing the hosts info in ansible hosts file
    proxy inf in ansible proxy file
    : param proxy_dict: proxy data in the dictionary format
    : return ret :
    """
    logger.info("\n Argument List:" + "\n proxy_dict:" + str(proxy_dict) + "\n dpdk:" + dpdk)
    # code to add ip to the /etc/anisble/hosts file
    ret = True

    if proxy_dict:
        logger.debug("Adding proxies")
        proxy_file_in = open(consts.PROXY_DATA_FILE, "r+")
        proxy_file_in.seek(0)
        proxy_file_in.truncate()
        proxy_file_out = open(consts.PROXY_DATA_FILE, "w")
        proxy_file_out.write("---")
        proxy_file_out.write("\n")
        for key, value in proxy_dict.iteritems():
            if value == '':
                value = "\"\""
            logger.info("Key Value pair " + key + ":" + value)
            logger.debug("Proxies added in file:" + key + ":" + value)
            proxy_file_out.write(key + ": " + str(value) + "\n")
        proxy_file_out.close()
        proxy_file_in.close()
        logger.info('Exit')
    return ret

def clean_up_k8_addons(**k8_addon):
    """
    function to delete all addons : such as metrics server
    :param k8_addon:
    :return:
    """
    logger.info("\n Argument List:" + "\n k8_addon:" + str(k8_addon))
    return_stmt = False
    hostname_map = k8_addon.get("hostname_map")
    host_node_type_map = k8_addon.get("host_node_type_map")
    for addon in k8_addon:
        if addon == "metrics_server" and k8_addon.get("metrics_server"):
            return_stmt = clean_up_metrics_server(hostname_map,
                                                  host_node_type_map)

    logger.info('Exit')
    return return_stmt

def clean_sriov_rc_local(hosts_data_dict):
    for node in hosts_data_dict:
        for key in node:
            if key == "Sriov":
                all_hosts = node.get("Sriov")
                for host_data in all_hosts:
                    hostdetails = host_data.get("host")
                    networks = hostdetails.get("networks")
                    node_hostname = hostdetails.get("hostname")
                    for network in networks:
                        sriov_intf = network.get("sriov_intf")
                        ret_hosts = apbl.launch_ansible_playbook_clean_sriov_rc_local(
                            consts.K8_SRIOV_CLEAN_RC_LOCAL, node_hostname, sriov_intf)

    return ret_hosts

def clean_up_k8(git_branch, Project_name, multus_enabled_str):
    """
    This function is used for clean/Reset the kubernetes cluster
    """
    logger.info("\n Argument List:" + "\n git_branch:" + git_branch +
                "\n Project_name:" + Project_name +
                "\n multus_enabled_str:" + str(multus_enabled_str))
    playbook_path_delete_project_folder_k8 = consts.K8_REMOVE_FOLDER
    playbook_path_clean_k8 = consts.K8_CLEAN_UP
    playbook_path_delete_nodes_k8 = consts.K8_REMOVE_NODE_K8
    SRC_PACKAGE_PATH = consts.INVENTORY_SOURCE_FOLDER
    HOST_FILE_PATH = consts.HOSTS_FILE
    ANSIBLE_HOST_FILE_PATH = consts.ANSIBLE_HOSTS_FILE
    VARIABLE_FILE = consts.VARIABLE_FILE
    PROXY_DATA_FILE = consts.PROXY_DATA_FILE
    master_hostname = get_host_master_name(Project_name)
    host_name = master_hostname
    multus_enabled = str(multus_enabled_str)
    logger.info('multus_enabled_str : %s', multus_enabled)

    logger.info('pip install --upgrade ansible==2.4.1.0')
    command = "pip install --upgrade ansible==2.4.1.0"
    ret_val = subprocess.call(command, shell=True)
    if not ret_val:
        logger.info('error in pip install --upgrade ansible==2.4.1.0')

    logger.info('EXECUTING CLEAN K8 CLUSTER PLAY')
    logger.info(playbook_path_clean_k8)
    ret_val = apbl.launch_ansible_playbook_clean_k8(playbook_path_clean_k8,
                                                    SRC_PACKAGE_PATH,
                                                    VARIABLE_FILE,
                                                    PROXY_DATA_FILE,
                                                    git_branch,
                                                    Project_name)
    if not ret_val:
        logger.error('FAILED IN CLEAN UP KUBERNETES CLUSTER ')
        exit(1)
    host_name_map_ip = get_hostname_ip_map_list(Project_name)
    for host_name, ip in host_name_map_ip.iteritems():
        logger.info('EXECUTING DELETE NODES PLAY')
        logger.info(playbook_path_delete_nodes_k8)
        ret_val = apbl.launch_delete_host_k8(playbook_path_delete_nodes_k8,
                                             ip, host_name, HOST_FILE_PATH,
                                             ANSIBLE_HOST_FILE_PATH,
                                             VARIABLE_FILE, Project_name,
                                             multus_enabled)
        if not ret_val:
            logger.error('FAILED IN DELTING NODE')
            exit(1)
    logger.info('EXECUTING REMOVE PROJECT FOLDER PLAY')
    logger.info(playbook_path_delete_project_folder_k8)
    ret_val = apbl.launch_delete_project_folder(
        playbook_path_delete_project_folder_k8, VARIABLE_FILE,
        SRC_PACKAGE_PATH, Project_name, PROXY_DATA_FILE)
    if not ret_val:
        logger.error('FAILED IN CLEAN UP KUBERNETES CLUSTER ')
        exit(1)

    logger.info('Exit')
    return ret_val

def clean_up_k8_docker(host_dict):
    """
    This function is used for clean docker on cluster nodes
    :param host_name_list : host_dict
    """
    logger.info("\n Argument List: host_dict is %s", host_dict)
    for host_name in host_dict:
        ret_val = apbl.launch_ansible_playbook_clean_docker(
            consts.K8_DOCKER_CLEAN_UP_ON_NODES, host_name)
        if not ret_val:
            logger.error('FAILED IN CLEAN UP KUBERNETES CLUSTER ')
            exit(1)
    return ret_val

def clean_up_k8_nodes(host_name_list, dynamic_hostname_map,
                      dynamic_host_node_type_map, Project_name,
                      multus_enabled_str):
    """
    This function is used for clean/Reset the specific node of kubernet cluster
    :param host_name_list : list of all the host names
    """
    logger.info("\n Argument List:" + "\n host_name_list:" + str(host_name_list) +
                "\n dynamic_hostname_map:" + str(dynamic_hostname_map) +
                "\n dynamic_host_node_type_map:" + str(dynamic_host_node_type_map) +
                "\n Project_name:" + Project_name +
                "\n multus_enabled_str:" + str(multus_enabled_str))

    playbook_path_clean_k8_nodes = consts.K8_CLEAN_UP_NODES
    playbook_path_delete_node_k8 = consts.K8_DELETE_NODE
    SRC_PACKAGE_PATH = consts.INVENTORY_SOURCE_FOLDER
    playbook_path_delete_nodes_k8 = consts.K8_REMOVE_NODE_K8
    HOST_FILE_PATH = consts.HOSTS_FILE
    ANSIBLE_HOST_FILE_PATH = consts.ANSIBLE_HOSTS_FILE
    VARIABLE_FILE = consts.VARIABLE_FILE
    PROXY_DATA_FILE = consts.PROXY_DATA_FILE
    master_hostname = get_host_master_name(Project_name)
    multus_enabled = str(multus_enabled_str)
    logger.info('multus_enabled_str : %s', multus_enabled)

    for host_name, ip in dynamic_hostname_map.iteritems():
        logger.info('EXECUTING CLEAN K8 NODE PLAY')
        logger.info(playbook_path_clean_k8_nodes)
        ret_val = apbl.launch_ansible_playbook_dynamic_k8_nodes_delete(
            playbook_path_clean_k8_nodes, host_name, SRC_PACKAGE_PATH,
            VARIABLE_FILE, PROXY_DATA_FILE, master_hostname,
            Project_name, multus_enabled)
        if not ret_val:
            logger.error('FAILED IN DELTING NODE')
            exit(1)

        logger.info('EXECUTING REMOVE NODE FROM INVENTORY PLAY')
        logger.info(playbook_path_delete_node_k8)
        ret_val = apbl.launch_ansible_playbook_delete_node(
            playbook_path_delete_node_k8, host_name,
            SRC_PACKAGE_PATH, VARIABLE_FILE, Project_name)
        if not ret_val:
            logger.error('FAILED IN DELTING NODE')
            exit(1)
        logger.info('EXECUTING REMOVE NODE FROM /etc/hosts and /etc/ansible/hosts PLAY')
        logger.info(playbook_path_delete_nodes_k8)
        ret_val = apbl.launch_delete_host_k8(playbook_path_delete_nodes_k8,
                                             ip, host_name, HOST_FILE_PATH,
                                             ANSIBLE_HOST_FILE_PATH,
                                             VARIABLE_FILE, Project_name,
                                             multus_enabled)
        if not ret_val:
            logger.error('FAILED IN DELTING NODE')
            exit(1)
    logger.info('Exit')
    return ret_val

def launch_provisioning_kubernetes(host_name_map, host_node_type_map,
                                   host_port_map, service_subnet, pod_subnet,
                                   networking_plugin, docker_repo,
                                   hosts, git_branch, Project_name,
                                   config, ha_enabled, loadbalancer_dict=None):
    """
    This function is used for deploy the kubernet cluster
    """
    ret_val = False
    playbook_path_create_inventory_file = consts.K8_CREATE_INVENTORY_FILE
    playbook_path_node_labeling = consts.K8_NODE_LABELING
    playbook_path_set_packages = consts.K8_SET_PACKAGES
    playbook_conf_docker_repo = consts.K8_CONF_DOCKER_REPO
    playbook_private_docker_creation = consts.K8_PRIVATE_DOCKER
    playbook_path_set_launcher = consts.KUBERNETES_SET_LAUNCHER
    playbook_path_clone_code = consts.K8_CLONE_CODE
    playbook_path_create_inventory = consts.KUBERNETES_CREATE_INVENTORY
    playbook_path_new_inventory_file = consts.KUBERNETES_NEW_INVENTORY
    playbook_path_weave_scope = consts.KUBERNETES_WEAVE_SCOPE
    playbook_path_kube_proxy = consts.KUBERNETES_KUBE_PROXY

    PROXY_DATA_FILE = consts.PROXY_DATA_FILE
    VARIABLE_FILE = consts.VARIABLE_FILE
    SRC_PACKAGE_PATH = consts.INVENTORY_SOURCE_FOLDER
    APT_ARCHIVES_SRC = consts.APT_ARCHIVES_PATH
    CURRENT_DIR = consts.CWD

    for key, node_type in host_node_type_map.iteritems():
        if node_type == "master":
            master_hostname = key

    for host_name, ip in host_name_map.iteritems():
        registry_port = host_port_map.get(host_name)
        logger.info('EXECUTING SET HOSTS PLAY')
        logger.info(playbook_path_set_packages)
        ret_val = apbl.launch_ansible_playbook(playbook_path_set_packages,
                                               ip, host_name, PROXY_DATA_FILE,
                                               VARIABLE_FILE, APT_ARCHIVES_SRC,
                                               SRC_PACKAGE_PATH, registry_port)
        if not ret_val:
            logger.error('FAILED SET HOSTS PLAY')
            exit(1)

    if docker_repo:
        docker_ip = docker_repo.get(consts.IP)
        docker_port = docker_repo.get(consts.PORT)
        logger.info('EXECUTING CREATING PRIVATE DOCKER REPO PLAY')
        logger.info(playbook_private_docker_creation)
        ret_val = apbl.launch_ansible_playbook_creating_docker_repo(
            playbook_private_docker_creation, PROXY_DATA_FILE,
            VARIABLE_FILE, docker_ip, docker_port,
            APT_ARCHIVES_SRC, SRC_PACKAGE_PATH)
        if not ret_val:
            logger.error('FAILED IN  CREATING PRIVATE DOCKER REPO ')
            exit(1)
        for host_name, ip in host_name_map.iteritems():
            logger.info('EXECUTING CONFIGURE DOCKER REPO PLAY')
            logger.info(playbook_conf_docker_repo)
            ret_val = apbl.launch_ansible_playbook_docker_conf(
                playbook_conf_docker_repo, ip, host_name,
                PROXY_DATA_FILE, VARIABLE_FILE, docker_ip, docker_port)
            if not ret_val:
                logger.error('FAILED IN CONFIGURE DOCKER REPO')
                exit(1)

    logger.info('CREATING INVENTORY FILE PLAY')
    logger.info(playbook_path_create_inventory_file)
    ret_val = apbl.creating_inventory_file(
        playbook_path_create_inventory_file, SRC_PACKAGE_PATH,
        VARIABLE_FILE, CURRENT_DIR, Project_name)
    if not ret_val:
        logger.error('CREATING INVENTORY FILE')
        exit(1)
    logger.info('EXECUTING MODIFIY INVENTORY FILES PLAY')
    logger.info(playbook_path_new_inventory_file)
    ret_val = modify_inventory_file(playbook_path_new_inventory_file,
                                    playbook_path_create_inventory,
                                    host_name_map,
                                    host_node_type_map, Project_name)
    if not ret_val:
        logger.error('FAILED TO MODIFIY INVENTORY FILES')
        exit(1)

    logger.info('EXECUTING CLONE KUBESPRAY CODE PLAY')
    logger.info(playbook_path_clone_code)
    ret_val = apbl.launch_clone_kubespray_play(playbook_path_clone_code,
                                               PROXY_DATA_FILE, VARIABLE_FILE,
                                               SRC_PACKAGE_PATH, git_branch,
                                               Project_name)
    if not ret_val:
        logger.error('FAILED TO CLON KUBESPRAY CODE')
        exit(1)

    logging = config.get(consts.KUBERNETES).get(consts.ENABLE_LOGGING)
    if logging != None:
        if logging != True and logging != False:
            logger.error('either enabled logging or disabled logging')
            exit(1)
        value = "False"
        if logging:
            value = "True"
            log_level = config.get(consts.KUBERNETES).get(consts.LOG_LEVEL)
            if log_level != "fatal" and log_level != "warning" and \
                log_level != "info" and log_level != "debug" and \
                log_level != "critical":
                logger.error('enter valid log_level')
                exit(1)
            logging_port = config.get(consts.KUBERNETES).get(consts.LOGGING_PORT)
            ret_val = enable_cluster_logging(value, Project_name,
                                             log_level, logging_port)
            if not ret_val:
                logger.error('failed to enable logging ')
    else:
        logger.info('logging is disabled ')


    if config.get(consts.KUBERNETES).get(consts.CPU_ALLOCATION_SUPPORT):
        if config.get(consts.KUBERNETES).get(consts.CPU_ALLOCATION_SUPPORT):
            cpu_manger_obj = CpuPinningConfiguration()
            if cpu_manger_obj.launch_cpu_pinning_kubernetes(config, PROXY_DATA_FILE, VARIABLE_FILE):
                logger.info('CPU ALLOCATION DONE SUCCESSFULLY')
            else:
                logger.error('CPU ALLOCATION FAILED')
                exit(1)
        else:
            logger.info('Exclusive_CPU_alloc_support: %s',
                        str(config.get(consts.KUBERNETES).get(consts.CPU_ALLOCATION_SUPPORT)))

    logger.info('pip install --upgrade ansible==2.4.1.0')
    command = "pip install --upgrade ansible==2.4.1.0"
    ret_val = subprocess.call(command, shell=True)
    if not ret_val:
        logger.info('error in pip install --upgrade ansible==2.4.1.0')

    logger.info('EXECUTING CONFIGURATION AND INSTALLATION OF KUBERNETES CLUSTER')
    logger.info(playbook_path_set_launcher)
    ret_val = apbl.launch_ansible_playbook_k8(playbook_path_set_launcher,
                                              service_subnet, pod_subnet,
                                              networking_plugin, PROXY_DATA_FILE,
                                              VARIABLE_FILE, SRC_PACKAGE_PATH,
                                              CURRENT_DIR, git_branch, Project_name)
    if not ret_val:
        logger.error('FAILED IN CONFIGURATION AND INSTALLATION OF KUBERNETES CLUSTER')
        exit(1)

    logger.info('Calling kubectl installation function')
    KubectlConfiguration().install_kubectl(host_name_map, host_node_type_map,
                                           ha_enabled, Project_name, config,
                                           VARIABLE_FILE, SRC_PACKAGE_PATH)

    if hosts:
        for i in range(len(hosts)):
            label_key = hosts[i].get(consts.HOST).get(consts.LABEL_KEY)
            hostname = hosts[i].get(consts.HOST).get(consts.HOSTNAME)
            label_value = hosts[i].get(consts.HOST).get(consts.LABEL_VALUE)
            logger.info(playbook_path_node_labeling)
            ret_val = apbl.launch_ansible_playbook_node_labeling(
                playbook_path_node_labeling, master_hostname,
                hostname, label_key, label_value, PROXY_DATA_FILE)
            if not ret_val:
                logger.error('FAILED IN INSTALLING FILE PLAY')
                exit(1)

    for host_name, node_type in host_node_type_map.iteritems():
        if  node_type == "master":
            logger.info('EXECUTING WEAVE SCOPE PLAY')
            logger.info(playbook_path_weave_scope)
            ret_val = apbl.launch_ansible_playbook_weave_scope(
                playbook_path_weave_scope, host_name, SRC_PACKAGE_PATH,
                VARIABLE_FILE, PROXY_DATA_FILE)
            if not ret_val:
                logger.error('FAILED IN INSTALLING FILE PLAY')
                exit(1)

            logger.info('EXECUTING KUBE PROXY PLAY')
            ret_val = apbl.launch_ansible_playbook_kube_proxy(
                playbook_path_kube_proxy, host_name, SRC_PACKAGE_PATH,
                VARIABLE_FILE, PROXY_DATA_FILE)
            if not ret_val:
                logger.error('FAILED IN KUBE PROXY FILE PLAY')
                exit(1)
            else:
                logger.info('Started KUBE PROXY')

    logger.info('Completed launch_provisioning_kubernetes()')
    logger.info('Exit')
    return ret_val

def modify_user_list(user_name, user_password, user_id):
    logger.info("\n Argument List:" + "\n user_name:" + user_name +
                "\n user_password:" + user_password + "\n user_id:" + user_id)

    SRC_PACKAGE_PATH = consts.INVENTORY_SOURCE_FOLDER
    logger.info('EXECUTING SET Authentication HOSTS PLAY')
    playbook_path_user_list = consts.KUBERNETES_USER_LIST
    logger.info(playbook_path_user_list)
    ret_val = apbl.launch_ansible_playbook_update_user_list(
        playbook_path_user_list, user_name, user_password,
        user_id, SRC_PACKAGE_PATH)
    if not ret_val:
        logger.error('FAILED SET HOSTS PLAY')
        exit(1)

    logger.info('Exit')
    return ret_val

def update_kube_api_manifest_file(master_host_name):
    logger.info("\n Argument List:" + "\n master_host_name:" + master_host_name)

    VARIABLE_FILE = consts.VARIABLE_FILE
    SRC_PACKAGE_PATH = consts.INVENTORY_SOURCE_FOLDER
    logger.info('EXECUTING SET Authentication HOSTS PLAY')
    playbook_path_authentication = consts.KUBERNETES_AUTHENTICATION
    logger.info(playbook_path_authentication)
    ret_val = apbl.launch_ansible_playbook_authentication(
        playbook_path_authentication, master_host_name,
        SRC_PACKAGE_PATH, VARIABLE_FILE)
    if not ret_val:
        logger.error('FAILED SET HOSTS PLAY')
        exit(1)

    logger.info('Exit')
    return ret_val

def _modifying_etcd_node(master_host_name):
    logger.info("\n Argument List:" + "\n master_host_name:" + master_host_name)

    VARIABLE_FILE = consts.VARIABLE_FILE
    SRC_PACKAGE_PATH = consts.INVENTORY_SOURCE_FOLDER
    logger.info('EXECUTING SET Authentication HOSTS PLAY')
    playbook_path_etcd_changes = consts.ETCD_CHANGES
    logger.info(playbook_path_etcd_changes)
    ret_val = apbl.launch_ansible_playbook_etcd_changes(
        playbook_path_etcd_changes, master_host_name,
        SRC_PACKAGE_PATH, VARIABLE_FILE)
    if not ret_val:
        logger.error('FAILED SET HOSTS PLAY')
        exit(1)

    logger.info('Exit')
    return ret_val

def modify_inventory_file(playbook1, playbook2, host_name_map, host_node_type_map, Project_name):
    logger.info("\n Argument List:" + "\n playbook1:" + playbook1 +
                "\n playbook2:" + playbook2 + "\n host_name_map:" + str(host_name_map) +
                "\n host_node_type_map:" + str(host_node_type_map) +
                "\n Project_name:" + Project_name)

    VARIABLE_FILE = consts.VARIABLE_FILE
    SRC_PACKAGE_PATH = consts.INVENTORY_SOURCE_FOLDER
    CURRENT_DIR = consts.CWD
    for host_name, ip in host_name_map.iteritems():
        logger.info('EXECUTING MODIFIED INVENTORY FILE PLAY')
        logger.info(playbook1)
        ret_val = apbl.launch_ansible_playbook_new_inventory(
            playbook1, ip, host_name, SRC_PACKAGE_PATH,
            VARIABLE_FILE, CURRENT_DIR, Project_name)
        if not ret_val:
            logger.error('FAILED IN MODIFIED INVENTORY FILE PLAY')
            exit(1)

    for host_name, node_type in host_node_type_map.iteritems():
        logger.info('EXECUTING MODIFIED INVENTORY FILE PLAY')
        logger.info(playbook2)
        ret_val = apbl.launch_ansible_playbook_inventory(
            playbook2, node_type, host_name, SRC_PACKAGE_PATH, VARIABLE_FILE,
            Project_name)
        if not ret_val:
            logger.error('FAILED IN MODIFIED INVENTORY FILE PLAY')
            exit(1)

    logger.info('Exit')
    return ret_val

def launch_crd_network(host_name_map, host_node_type_map):
    """
    This function is used to create crd network
    """
    logger.info("\n Argument List:" + "\n host_name_map:" + str(host_name_map) +
                "\n host_node_type_map:" + str(host_node_type_map))

    playbook_path_create_crd_network = consts.K8_CREATE_CRD_NETWORK
    PROXY_DATA_FILE = consts.PROXY_DATA_FILE
    SRC_PACKAGE_PATH = consts.INVENTORY_SOURCE_FOLDER
    for host_name, node_type in host_node_type_map.iteritems():
        for key, value in host_name_map.iteritems():
            if node_type == "master" and key == host_name:
                master_ip = value
                master_host_name = key
                logger.info('master IP is %s', master_ip)
                logger.info('master hostname is %s', master_host_name)

    logger.info('EXECUTING CRD NETWORK CREATION PLAY. Master ip - %s, Master Host Name - %s'
                %(master_ip, master_host_name))
    logger.info(playbook_path_create_crd_network)
    ret_val = apbl.launch_ansible_playbook_create_crd_network(
        playbook_path_create_crd_network, master_ip, master_host_name,
        SRC_PACKAGE_PATH, PROXY_DATA_FILE)
    if not ret_val:
        logger.error('FAILED IN CREATING CRD NETWORK')
        exit(1)

    logger.info('Exit')
    return ret_val


def launch_multus_cni(host_name_map, host_node_type_map, service_subnet,
                      pod_subnet, networking_plugin):
    """
    This function is used to launch multus cni
    """
    logger.info("\n Argument List:" + "\n host_name_map:" +
                str(host_name_map) + "\n host_node_type_map:" +
                str(host_node_type_map) + "\n service_subnet:" +
                service_subnet + "\n pod_subnet:" + pod_subnet +
                "\n networking_plugin:" + networking_plugin)

    ret_val = False
    playbook_path_set_master_multus = consts.K8_MULTUS_SET_MASTER
    playbook_path_scp_multus = consts.K8_MULTUS_SCP_MULTUS_CNI
    playbook_path_set_node_multus = consts.K8_MULTUS_SET_NODE
    PROXY_DATA_FILE = consts.PROXY_DATA_FILE
    SRC_PACKAGE_PATH = consts.INVENTORY_SOURCE_FOLDER
    logger.info('EXECUTING MULTUS CNI PLAY')
    for key, value in host_node_type_map.iteritems():
        node_type = value
        host_name = key
        logger.info(playbook_path_set_master_multus)
        for key, value in host_name_map.iteritems():
            ip = value
            host_name1 = key
            if node_type == "master" and host_name1 == host_name:
                logger.info('IP is %s', ip)
                logger.info('Host name is %s', host_name)
                logger.info('EXECUTING MASTER MULTUS PLAY')
                ret_val = apbl.launch_ansible_playbook_master_multus(
                    playbook_path_set_master_multus, ip, host_name,
                    networking_plugin, SRC_PACKAGE_PATH, PROXY_DATA_FILE)
                if not ret_val:
                    logger.error('FAILED IN INSTALLING MULTUS AT MASTER')
                    exit(1)
            elif node_type == "minion" and host_name1 == host_name:
                logger.info('IP is %s', ip)
                logger.info('Host name is %s', host_name)
                logger.info('EXECUTING SCP MULTUS PLAY')
                ret_val = apbl.launch_ansible_playbook_scp_multus(
                    playbook_path_scp_multus, ip, host_name,
                    networking_plugin, SRC_PACKAGE_PATH)
                if not ret_val:
                    logger.error('FAILED IN SCP MULTUS AT NODE')
                    exit(1)
                logger.info('EXECUTING NODE MULTUS PLAY')
                ret_val = apbl.launch_ansible_playbook_node_multus(
                    playbook_path_set_node_multus, ip, host_name,
                    networking_plugin, SRC_PACKAGE_PATH)
                if not ret_val:
                    logger.error('FAILED IN INSTALLING MULTUS AT NODE')
                    exit(1)

    logger.info('Exit')
    return ret_val


def launch_sriov_cni_configuration(host_name_map, host_node_type_map,
                                   hosts_data_dict, Project_name):
    """
    This function is used to launch sriov cni
    """
    logger.info("\n Argument List:" + "\n host_name_map:" +
                str(host_name_map) + "\n host_node_type_map:" +
                str(host_node_type_map) + "\n hosts_data_dict:" +
                str(hosts_data_dict) + "\n Project_name:" + Project_name)

    playbook_path_sriov_build_cni = consts.K8_SRIOV_CNI_BUILD
    playbook_path_sriov_dpdk_cni = consts.K8_SRIOV_DPDK_CNI
    playbook_path_sriov_dpdk_cni_bin_inst = consts.K8_SRIOV_DPDK_CNI_BIN_INST
    playbook_path_dpdk_driver_load = consts.K8_SRIOV_DPDK_DRIVER_LOAD
    playbook_path_sriov_cni_bin_inst = consts.K8_SRIOV_CNI_BIN_INST
    playbook_path_sriov_cni_enable = consts.K8_SRIOV_ENABLE
    playbook_path_sriov_configuration_script = consts.K8_SRIOV_CONFIG_SCRIPT
    PROXY_DATA_FILE = consts.PROXY_DATA_FILE
    SRC_PACKAGE_PATH = consts.K8_SOURCE_PATH
    minion_list = []
    logger.info('EXECUTING SRIOV CNI PLAY')
    logger.info("INSIDE launch_sriov_cni")
    dpdk_enable = "no"

    VARIABLE_FILE = consts.VARIABLE_FILE
    config = file_utils.read_yaml(VARIABLE_FILE)
    project_path = config.get(consts.PROJECT_PATH)
    inventory_file_path = project_path + Project_name + "/k8s-cluster.yml"
    logger.info('Inventory file path is %s', inventory_file_path)
    with open(inventory_file_path) as f:
        for line in f:
            if "kube_network_plugin:" in line:
                network_plugin1 = line.split("kube_network_plugin:", 1)[1]
                networking_plugin = network_plugin1.strip(' \t\n\r')
                hostnamestringlist = line.split(" ")
                networkPluginName = hostnamestringlist[0]
                networkPluginName = networkPluginName.strip(' \t\n\r')
                logger.info('Network_plugin is %s', networking_plugin)

    for node in hosts_data_dict:
        for key in node:
            if key == "Sriov":
                all_hosts = node.get("Sriov")
                logger.info('Host list is %s', all_hosts)
                for host_data in all_hosts:
                    logger.info('Host data is %s', host_data)
                    hostdetails = host_data.get("host")
                    hostname = hostdetails.get("hostname")
                    networks = hostdetails.get("networks")
                    logger.info('Hostname is %s', hostname)
                    minion_list.append(hostname)
                    for network in networks:
                        dpdk_driver = 'vfio-pci'
                        dpdk_enable = network.get("dpdk_enable")
                        sriov_intf = network.get("sriov_intf")
                        logger.info('SRIOV CONFIGURATION ON NODES')
                        ret_val = apbl.launch_ansible_playbook_enable_sriov(
                            playbook_path_sriov_cni_enable, hostname, sriov_intf,
                            playbook_path_sriov_configuration_script,
                            networking_plugin)

    ret_val = apbl.launch_ansible_playbook_build_sriov(
        playbook_path_sriov_build_cni, SRC_PACKAGE_PATH, PROXY_DATA_FILE)
    logger.info('DPDK flag is %s', dpdk_enable)
    if dpdk_enable == "yes":
        ret_val = apbl.launch_ansible_playbook_build_sriov_dpdk(
            playbook_path_sriov_dpdk_cni, SRC_PACKAGE_PATH, PROXY_DATA_FILE)
    for  host_name in get_master_host_name_list(host_node_type_map):
        logger.info('Executing for master %s', str(host_name))
        logger.info('INSTALLING SRIOV BIN ON MASTER')
        ret_val = apbl.launch_ansible_playbook_sriov_install(
            playbook_path_sriov_cni_bin_inst, host_name, SRC_PACKAGE_PATH)
        if dpdk_enable == "yes":
            logger.info('INSTALLING SRIOV DPDK BIN ON MASTER')
            ret_val = apbl.launch_ansible_playbook_sriov_dpdk_install(
                playbook_path_sriov_dpdk_cni_bin_inst, host_name, SRC_PACKAGE_PATH)

    for  host_name in minion_list:
        logger.info('Executing for  minion %s', str(host_name))
        logger.info('INSTALLING SRIOV BIN ON WORKER nodes')
        ret_val = apbl.launch_ansible_playbook_sriov_install(
            playbook_path_sriov_cni_bin_inst, host_name, SRC_PACKAGE_PATH)
        if dpdk_enable == "yes":
            logger.info('INSTALLING SRIOV DPDK BIN ON WORKERS')
            ret_val = apbl.launch_ansible_playbook_dpdk_driver_load(
                playbook_path_dpdk_driver_load, host_name, dpdk_driver)
            ret_val = apbl.launch_ansible_playbook_sriov_dpdk_install(
                playbook_path_sriov_dpdk_cni_bin_inst, host_name, SRC_PACKAGE_PATH)
    return ret_val

def launch_sriov_network_creation(host_name_map, host_node_type_map,
                                  hosts_data_dict, Project_name):
    logger.info("\n Argument List:" + "\n host_name_map:" + str(host_name_map) +
                "\n host_node_type_map:" + str(host_node_type_map) +
                "\n hosts_data_dict:" + str(hosts_data_dict) +
                "\n Project_name:" + Project_name)

    ret_val = False
    playbook_path_cr_sriov_nw = consts.K8_SRIOV_CR_NW
    dpdk_enable = "no"
    playbook_path_cr_sriov_dpdk_nw = consts.K8_SRIOV_DPDK_CR_NW
    playbook_path_cr_sriov_dhcp_nw = consts.K8_SRIOV_DHCP_CR_NW
    playbook_path_sriov_conf = consts.K8_SRIOV_CONF
    master_list = get_master_host_name_list(host_node_type_map)
    logger.info('Master list is %s', master_list)
    masterHost = get_host_master_name(Project_name)
    PROXY_DATA_FILE = consts.PROXY_DATA_FILE
    #for masterHost in master_list:
    logger.info('Performing config for node %s', str(masterHost))
    for node in hosts_data_dict:
        for key in node:
            if key == "Sriov":
                all_hosts = node.get("Sriov")
                for host_data in all_hosts:
                    hostdetails = host_data.get("host")
                    networks = hostdetails.get("networks")
                    node_hostname = hostdetails.get("hostname")
                    for network in networks:
                        dpdk_tool = '/etc/cni/scripts/dpdk-devbind.py'
                        dpdk_driver = 'vfio-pci'
                        dpdk_enable = network.get("dpdk_enable")
                        rangeEnd = network.get("rangeEnd")
                        rangeStart = network.get("rangeStart")
                        host = network.get("type")
                        sriov_gateway = network.get("sriov_gateway")
                        sriov_intf = network.get("sriov_intf")
                        sriov_subnet = network.get("sriov_subnet")
                        sriov_nw_name = network.get("network_name")
                        masterPlugin = network.get(consts.MASTER_PLUGIN)
                        logger.info('Master host is %s', masterHost)
                        logger.info('Node hostname is %s', node_hostname)
                        logger.info('dpdk_tool: %s', dpdk_tool)
                        logger.info('dpdk_driver: %s', dpdk_driver)
                        logger.info('dpdk_enable: %s', dpdk_enable)
                        logger.info('sriov_intf: %s', sriov_intf)
                        logger.info('masterHost: %s', masterHost)
                        logger.info('sriov_nw_name: %s', sriov_nw_name)
                        logger.info('rangeStart:%s', rangeStart)
                        logger.info('rangeEnd: %s', rangeEnd)
                        logger.info('sriov_subnet: %s', sriov_subnet)
                        logger.info('sriov_gateway : %s', sriov_gateway)
                        if dpdk_enable == "yes":
                            logger.info('SRIOV NETWORK CREATION STARTED USING DPDK DRIVER')
                            ret_val = apbl.launch_ansible_playbook_sriov_dpdk_crd_nw(
                                playbook_path_cr_sriov_dpdk_nw, playbook_path_sriov_conf,
                                sriov_intf, masterHost, sriov_nw_name, dpdk_driver,
                                dpdk_tool, node_hostname, masterPlugin)

                        if dpdk_enable == "no":
                            if host == "host-local":
                                logger.info('SRIOV NETWORK CREATION STARTED USING KERNEL DRIVER WITH IPAM host-local')
                                ret_val = apbl.launch_ansible_playbook_sriov_crd_nw(
                                    playbook_path_cr_sriov_nw, playbook_path_sriov_conf,
                                    sriov_intf, masterHost, sriov_nw_name, rangeStart,
                                    rangeEnd, sriov_subnet, sriov_gateway, masterPlugin)

                            if host == "dhcp":
                                logger.info('SRIOV NETWORK CREATION STARTED USING KERNEL DRIVER WITH IPAM host-dhcp')
                                ret_val = apbl.launch_ansible_playbook_sriov_dhcp_crd_nw(
                                    playbook_path_cr_sriov_dhcp_nw, playbook_path_sriov_conf,
                                    sriov_intf, masterHost, sriov_nw_name, PROXY_DATA_FILE)

    logger.info('Exit')
    return ret_val

def get_master_host_name_list(host_node_type_map):
    logger.info("\n Argument List:" + "\n host_node_type_map:" + str(host_node_type_map))

    masterList = []
    logger.info('host_node_type_map is: %s', str(host_node_type_map))
    for key, value in host_node_type_map.iteritems():
        if value == "master":
            masterList.append(key)

    logger.info('Exit')
    return masterList

def delete_existing_conf_files(dynamic_hostname_map, dynamic_host_node_type_map, Project_name):
    """
    This function is used to delete existing conf files
    """
    logger.info("\n Argument List:" + "\n dynamic_hostname_map:" + str(dynamic_hostname_map) +
                "\n dynamic_host_node_type_map:" + str(dynamic_host_node_type_map) +
                "\n Project_name:" + Project_name)

    ret_val = False
    playbook_path_conf_delete_existing_conf_files = consts.K8_CONF_FILES_DELETION_AFTER_MULTUS
    #K8_CONF_FILES_DELETION_DYNAMIC_CODE
    SRC_PACKAGE_PATH = consts.INVENTORY_SOURCE_FOLDER
    logger.info('DELETING EXISTING CONF FILES')
    VARIABLE_FILE = consts.VARIABLE_FILE
    config = file_utils.read_yaml(VARIABLE_FILE)
    project_path = config.get(consts.PROJECT_PATH)
    inventory_file_path = project_path + Project_name + "/k8s-cluster.yml"
    logger.info('Inventory file path is %s', inventory_file_path)
    with open(inventory_file_path) as f:
        for line in f:
            if "kube_network_plugin:" in line:
                network_plugin1 = line.split("kube_network_plugin:", 1)[1]
                networking_plugin = network_plugin1.strip(' \t\n\r')
                hostnamestringlist = line.split(" ")
                networkPluginName = hostnamestringlist[0]
                networkPluginName = networkPluginName.strip(' \t\n\r')
                logger.info('Network plugin is %s', networking_plugin)
        for key, value in dynamic_hostname_map.iteritems():
            ip = value
            host_name = key
            logger.info('IP is %s', ip)
            logger.info('Hostname is %s', host_name)
            logger.info('EXECUTING DELETE CONF FILES PLAY ON DYNAMIC NODE')
            ret_val = apbl.launch_ansible_playbook_delete_conf_files(
                playbook_path_conf_delete_existing_conf_files, ip, host_name,
                networking_plugin, SRC_PACKAGE_PATH)
            if not ret_val:
                logger.error('FAILED IN DELETING CONF FILES ON DYNAMIC NODE')
                exit(1)

    logger.info('Exit')
    return ret_val

def delete_existing_conf_files_after_additional_plugins(host_name_map,
                                                        host_node_type_map,
                                                        networking_plugin):
    """
    This function is used to delete existing conf files
    """
    logger.info("\n Argument List:" + "\n host_name_map:" + str(host_name_map) +
                "\n host_node_type_map:" + str(host_node_type_map) +
                "\n networking_plugin:" + networking_plugin)

    ret_val = False
    playbook_path_conf_delete_existing_conf_files_after_multus = consts.K8_CONF_FILES_DELETION_AFTER_MULTUS
    SRC_PACKAGE_PATH = consts.INVENTORY_SOURCE_FOLDER
    logger.info('DELETING EXISTING CONF FILES AFTER MULTUS')
    for key, value in host_node_type_map.iteritems():
        node_type = value
        host_name = key
        logger.info(playbook_path_conf_delete_existing_conf_files_after_multus)
        for key, value in host_name_map.iteritems():
            ip = value
            host_name1 = key
            if node_type == "minion" and host_name1 == host_name:
                logger.info('IP is %s', ip)
                logger.info('Hostname is %s', host_name)
                logger.info('EXECUTING DELETE CONF FILES PLAY')
                ret_val = apbl.launch_ansible_playbook_delete_conf_files(
                    playbook_path_conf_delete_existing_conf_files_after_multus,
                    ip, host_name, networking_plugin, SRC_PACKAGE_PATH)
                if not ret_val:
                    logger.error('FAILED IN DELETING CONF FILES')
                    exit(1)

    logger.info('Exit')
    return ret_val

def create_default_network(host_name_map, host_node_type_map, service_subnet,
                           pod_subnet, networking_plugin, item):
    """
    This function is create default network
    """
    logger.info("\n Argument List:" + "\n host_name_map:" + str(host_name_map) +
                "\n host_node_type_map:" + str(host_node_type_map) +
                "\n service_subnet:" + service_subnet +
                "\n pod_subnet:" + pod_subnet +
                "\n networking_plugin:" + networking_plugin +
                "\n item:" + str(item))

    playbook_path_set_create_default_network = consts.K8_CREATE_DEFAULT_NETWORK
    PROXY_DATA_FILE = consts.PROXY_DATA_FILE
    SRC_PACKAGE_PATH = consts.INVENTORY_SOURCE_FOLDER
    logger.info('EXECUTING CREATE DEFAULT NETWORK PLAY')

    subnet = item.get(consts.POD_SUBNET)
    networkName = item.get(consts.NETWORK_NAME)
    masterPlugin = item.get(consts.MASTER_PLUGIN)
    logger.info('subnet is %s', subnet)
    logger.info('networkName is %s', networkName)

    for key, value in host_node_type_map.iteritems():
        node_type = value
        host_name = key
        for key, value in host_name_map.iteritems():
            ip = value
            host_name1 = key
            if node_type == "master" and host_name1 == host_name:
                master_ip = ip
                master_host_name = host_name

    logger.info('DELETING FLANNEL INTERFACE.. Master ip - %s, Master Host Name - %s'
                % (master_ip, master_host_name))
    logger.info(playbook_path_set_create_default_network)
    ret_val = apbl.launch_ansible_playbook_create_default_network(
        playbook_path_set_create_default_network, master_ip, master_host_name,
        networkName, subnet, networking_plugin, masterPlugin, SRC_PACKAGE_PATH,
        PROXY_DATA_FILE)
    if not ret_val:
        logger.error('FAILED IN CREATING DEFAULT NETWORK')

    logger.info('Exit')
    return ret_val

def launch_flannel_interface(host_name_map, host_node_type_map, networking_plugin, item):
    """
    This function is used to launch flannel interface
    """
    logger.info("\n Argument List:" + "\n host_name_map:" + str(host_name_map) +
                "\n host_node_type_map:" + str(host_node_type_map) +
                "\n networking_plugin:" + networking_plugin + "\n item:" + item)

    playbook_path_conf_flannel_intf_at_master = consts.K8_CONF_FLANNEL_INTERFACE_AT_MASTER
    playbook_path_conf_flannel_intf_at_node = consts.K8_CONF_FLANNEL_INTERFACE_AT_NODE
    SRC_PACKAGE_PATH = consts.INVENTORY_SOURCE_FOLDER
    logger.info('EXECUTING FLANNEL INTERFACE CREATION PLAY')
    networkDict = item.get("flannel_network")
    network = networkDict.get('network')
    subnetLen = networkDict.get('subnetLen')
    vni = networkDict.get('vni')

    for key, value in host_node_type_map.iteritems():
        node_type = value
        host_name = key
        logger.info(playbook_path_conf_flannel_intf_at_master)
        for key, value in host_name_map.iteritems():
            ip = value
            host_name1 = key
            if node_type == "master" and host_name1 == host_name:
                logger.info('IP is %s', ip)
                logger.info('Hostname is %s', host_name)
                master_ip = ip

                logger.info('master_ip is %s', master_ip)
                logger.info('network is %s', network)
                logger.info('subnetLen is %s', subnetLen)
                logger.info('vni is %s', vni)

                logger.info('EXECUTING FLANNEL INTF PLAY AT MASTER')
                ret_val = apbl.launch_ansible_playbook_master_flannel(
                    playbook_path_conf_flannel_intf_at_master, ip, host_name,
                    networking_plugin, network, subnetLen, vni, SRC_PACKAGE_PATH)
                if not ret_val:
                    logger.error('FAILED IN CONFIGURING FLANNEL INTERFACE AT MASTER')
                    exit(1)

    for key, value in host_node_type_map.iteritems():
        node_type = value
        host_name = key
        logger.info(playbook_path_conf_flannel_intf_at_master)
        for key, value in host_name_map.iteritems():
            ip = value
            host_name1 = key
            if node_type == "minion" and host_name1 == host_name:
                logger.info('IP is %s', ip)
                logger.info('Hostname is %s', host_name)
                logger.info('master_ip is %s', master_ip)
                logger.info('network is %s', network)
                logger.info('subnetLen is %s', subnetLen)
                logger.info('vni is %s', vni)

                logger.info('EXECUTING FLANNEL INTF PLAY AT NODE')
                ret_val = apbl.launch_ansible_playbook_node_flannel(
                    playbook_path_conf_flannel_intf_at_node, ip, host_name,
                    networking_plugin, network, subnetLen, vni, master_ip,
                    SRC_PACKAGE_PATH)
                if not ret_val:
                    logger.error('FAILED IN CONFIGURING FLANNEL INTERFACE AT NODE')
                    exit(1)

    logger.info('Exit')
    return ret_val


def create_flannel_networks(host_name_map, host_node_type_map,
                            networking_plugin, item):
    """
    This function is used to create flannel networks
    """
    logger.info("\n Argument List:" + "\n host_name_map:" + str(host_name_map) +
                "\n host_node_type_map:" + str(host_node_type_map) +
                "\n networking_plugin:" + networking_plugin + "\n item:" + item)

    playbook_path_conf_flannel_network_creation = consts.K8_CONF_FLANNEL_NETWORK_CREATION
    PROXY_DATA_FILE = consts.PROXY_DATA_FILE
    SRC_PACKAGE_PATH = consts.INVENTORY_SOURCE_FOLDER
    logger.info('CREATING FLANNEL NETWORK')
    networkDict = item.get("flannel_network")
    networkName = networkDict.get('network_name')
    vni = networkDict.get('vni')
    logger.info('networkName is %s', networkName)
    logger.info('vni is %s', vni)
    vniInt = int(vni)
    vniTemp1 = (vniInt - 1)
    vniTemp = str(vniTemp1)

    for key, value in host_node_type_map.iteritems():
        node_type = value
        host_name = key
        logger.info(playbook_path_conf_flannel_network_creation)
        for key, value in host_name_map.iteritems():
            ip = value
            host_name1 = key
            if node_type == "master" and host_name1 == host_name:
                logger.info('IP is %s', ip)
                logger.info('Hostname is %s', host_name)
                logger.info('networkName is %s', networkName)
                logger.info('vni is %s', vni)

                logger.info('CREATING FLANNEL NETWORKS')
                ret_val = apbl.launch_ansible_playbook_create_flannel_networks(
                    playbook_path_conf_flannel_network_creation, ip, host_name,
                    networkName, vni, vniTemp, SRC_PACKAGE_PATH, PROXY_DATA_FILE)
                if not ret_val:
                    logger.error('FAILED IN CONFIGURING FLANNEL INTERFACE AT MASTER')
                    exit(1)
    logger.info('Exit')
    return ret_val


def create_flannel_interface(host_name_map, host_node_type_map,
                             networking_plugin, Project_name, hosts_data_dict):
    logger.info("\n Argument List:" + "\n host_name_map:" + str(host_name_map) +
                "\n host_node_type_map:" + str(host_node_type_map) +
                "\n networking_plugin:" + networking_plugin +
                "\n Project_name:" + Project_name +
                "\n hosts_data_dict:" + str(hosts_data_dict))

    ret_val = False
    playbook_path_conf_patch_node_master = consts.K8_CONF_FLANNEL_DAEMON_AT_MASTER
    playbook_path_conf_copy_flannel_yaml = consts.K8_CONF_COPY_FLANNEL_CNI
    playbook_path_conf_flannel_intf_at_master = consts.K8_CONF_FLANNEL_INTF_CREATION_AT_MASTER
    PROXY_DATA_FILE = consts.PROXY_DATA_FILE
    SRC_PACKAGE_PATH = consts.INVENTORY_SOURCE_FOLDER
    logger.info('EXECUTING FLANNEL INTERFACE CREATION PLAY IN CREATE FUNC')
    master_list = get_master_host_name_list(host_node_type_map)
    logger.info('master_list %s', str(master_list))
    masterHost = get_host_master_name(Project_name)
    logger.info('Performing config for node %s', str(masterHost))

    for item1 in hosts_data_dict:
        for key in item1:
            if key == "Multus_network":
                multus_network = item1.get("Multus_network")
                for item2 in multus_network:
                    for key in item2:
                        if key == "CNI_Configuration":
                            logger.info('CNI key is %s', key)
                            cni_configuration = item2.get("CNI_Configuration")
                            for item3 in cni_configuration:
                                for key in item3:
                                    logger.info('Network key is %s', key)
                                    logger.info('consts.FLANNEL_NETWORK value is %s', consts.FLANNEL_NETWORK)
                                    if consts.FLANNEL_NETWORK == key:
                                        all_hosts = item3.get(consts.FLANNEL_NETWORK)
                                        for host_data in all_hosts:
                                            hostdetails = host_data.get(consts.FLANNEL_NETWORK_DETAILS)
                                            networkName = hostdetails.get(consts.NETWORK_NAME)
                                            network = hostdetails.get(consts.NETWORK)
                                            cidr = hostdetails.get(consts.SUBNET)
                                            masterPlugin = hostdetails.get(consts.MASTER_PLUGIN)
                                            logger.info('network is %s', network)
                                            for key, value in host_node_type_map.iteritems():
                                                node_type = value
                                                host_name = key
                                                for key, value in host_name_map.iteritems():
                                                    ip = value
                                                    host_name1 = key
                                                    if node_type == "master" and host_name1 == host_name:
                                                        logger.info('ip: %s', ip)
                                                        logger.info('host_name: %s', host_name)
                                                        master_ip = ip
                                                        master_host_name = host_name
                                                        logger.info('master_ip :%s', master_ip)
                                                        logger.info('master_host_name :%s', master_host_name)
                                                        logger.info('Calling flannel daemon')
                                                        logger.info(
                                                            'Calling %s with IP - %s, network - %s, cidr - %s',
                                                            playbook_path_conf_patch_node_master,
                                                            master_ip, network, cidr)
                                                        ret_val = apbl.launch_ansible_playbook_flannel_daemon(
                                                            playbook_path_conf_patch_node_master,
                                                            master_ip, network, cidr,
                                                            masterPlugin, SRC_PACKAGE_PATH)
                                                        if not ret_val:
                                                            ret_val = False
                                                            logger.error('FAILED IN CREATING FLANNEL NETWORK')
                                                        else:
                                                            ret_val = True

                                                        ret_val = apbl.launch_ansible_playbook_copy_flannel_cni(
                                                            playbook_path_conf_copy_flannel_yaml,
                                                            master_ip, master_host_name, network,
                                                            SRC_PACKAGE_PATH)
                                                        if not ret_val:
                                                            ret_val = False
                                                            logger.error('FAILED IN COPYING FLANNEL CNI')

    logger.info('networkName is %s', networkName)

    if ret_val:
        time.sleep(30)
        ret_val = apbl.launch_ansible_playbook_create_flannel_interface(
            playbook_path_conf_flannel_intf_at_master, master_ip,
            master_host_name, networkName, network, masterPlugin,
            SRC_PACKAGE_PATH, PROXY_DATA_FILE)
        if not ret_val:
            ret_val = False
            logger.error('FAILED IN CREATING FLANNEL NETWORK')

    logger.info('Exit')
    return ret_val


def create_weave_interface(host_name_map, host_node_type_map, service_subnet,
                           pod_subnet, networking_plugin, item):
    """
    This function is used to create weave interace and network
    """
    logger.info("\n Argument List:" + "\n host_name_map:" + str(host_name_map) +
                "\n host_node_type_map:" + str(host_node_type_map) +
                "\n service_subnet:" + service_subnet +
                "\n pod_subnet:" + pod_subnet +
                "\n networking_plugin:" + networking_plugin +
                "\n item:" + item)

    ret_val = False
    playbook_path_conf_weave_network_creation = consts.K8_CONF_WEAVE_NETWORK_CREATION
    playbook_path_conf_weave_conf_deletion = consts.K8_CONF_FILES_DELETION_AFTER_MULTUS
    playbook_path_conf_copy_weave_yaml = consts.K8_CONF_COPY_WEAVE_CNI
    PROXY_DATA_FILE = consts.PROXY_DATA_FILE
    SRC_PACKAGE_PATH = consts.INVENTORY_SOURCE_FOLDER
    logger.info('CREATING WEAVE NETWORK')
    networkDict = item.get(consts.WEAVE_NETWORK_DETAILS)
    networkName = networkDict.get(consts.NETWORK_NAME)
    subnet = networkDict.get(consts.SUBNET)
    masterPlugin = networkDict.get(consts.MASTER_PLUGIN)
    logger.info('networkName is %s', networkName)
    logger.info('subnet is %s', subnet)

    for key, value in host_node_type_map.iteritems():
        node_type = value
        host_name = key
        logger.info(playbook_path_conf_weave_network_creation)
        for key, value in host_name_map.iteritems():
            ip = value
            host_name1 = key
            if node_type == "master" and host_name1 == host_name:
                logger.info('IP is %s', ip)
                master_ip = ip
                master_host_name = host_name
                ret_val = apbl.launch_ansible_playbook_copy_weave_cni(
                    playbook_path_conf_copy_weave_yaml, master_ip,
                    master_host_name, subnet, SRC_PACKAGE_PATH)
                if not ret_val:
                    logger.error('FAILED IN COPYING WEAVE CNI')
                    exit(1)

    logger.info('CREATING WEAVE NETWORKS.. Master ip - %s, Master host name - %s'
                %(master_ip, master_host_name))
    ret_val = apbl.launch_ansible_playbook_create_weave_network(
        playbook_path_conf_weave_network_creation, master_ip, master_host_name,
        networkName, subnet, masterPlugin, SRC_PACKAGE_PATH, PROXY_DATA_FILE)
    if not ret_val:
        logger.error('FAILED IN CONFIGURING WEAVE INTERFACE')
        exit(1)

    for key, value in host_node_type_map.iteritems():
        node_type = value
        host_name = key
        logger.info(playbook_path_conf_weave_conf_deletion)
        for key, value in host_name_map.iteritems():
            ip = value
            host_name1 = key
            if node_type == "minion" and host_name1 == host_name:
                logger.info('IP is %s', ip)
                logger.info('DELETING CONF FILE')
                ret_val = apbl.launch_ansible_playbook_delete_weave_conf(
                    playbook_path_conf_weave_conf_deletion, ip, host_name,
                    networking_plugin, SRC_PACKAGE_PATH)
                if not ret_val:
                    logger.error('FAILED IN CONFIGURING WEAVE INTERFACE')
                    exit(1)
    logger.info('Exit')
    return ret_val


def __hostname_list(hosts):
    logger.info("\n Argument List:" + "\n hosts:" + str(hosts))

    logger.info("Creating host name list")
    host_list = []
    for i in range(len(hosts)):
        host_name = ""
        name = hosts[i].get(consts.HOST).get(consts.HOST_NAME)
        if name:
            host_name = name
            host_list.append(host_name)
    logger.info('Exit')
    return host_list

def launch_metrics_server(hostname_map, host_node_type_map):
    logger.info("\n Argument List:" + "\n hostname_map:" + str(hostname_map) +
                "\n  host_node_type_map:" + str(host_node_type_map))
    ret_val = False
    logger.info("launch_metrics_server function")
    playbook_path_metrics_server = consts.K8_METRRICS_SERVER
    PROXY_DATA_FILE = consts.PROXY_DATA_FILE
    count = 0
    for host_name, node_type in host_node_type_map.iteritems():
        if node_type == "master" and count == 0:
            logger.info('CONFIGURING METRICS SERVER on --' + node_type +
                        "---> " + host_name + " ip --> " +
                        str(hostname_map[host_name]))
            count = count + 1
            ret_val = apbl.launch_ansible_playbook_metrics_server(
                playbook_path_metrics_server, hostname_map[host_name],
                host_name, PROXY_DATA_FILE)

    logger.info('Exit')
    return ret_val

def clean_up_metrics_server(hostname_map, host_node_type_map):
    logger.info("\n Argument List:" + "\n hostname_map:" + str(hostname_map) +
                "\n  host_node_type_map:" + str(host_node_type_map))
    PROXY_DATA_FILE = consts.PROXY_DATA_FILE

    logger.info('clean_up_metrics_server')
    ret_val = False
    count = 0

    for host_name, node_type in host_node_type_map.iteritems():
        if node_type == "master" and count == 0:
            count = count + 1
            logger.info('REMOVING METRICS SERVER on --' + node_type + "---> " +
                        host_name + " ip --> " + str(hostname_map[host_name]))
            ret_val = apbl.launch_ansible_playbook_metrics_server_clean(
                consts.K8_METRRICS_SERVER_CLEAN, hostname_map[host_name],
                host_name, PROXY_DATA_FILE)

    logger.info('Exit')
    return ret_val

def launch_ceph_kubernetes(host_name_map, host_node_type_map, hosts, ceph_hosts):
    """
    This function is used for deploy the ceph
    """
    logger.info("\n Argument List:" + "\n host_name_map:" + str(host_name_map) +
                "\n host_node_type_map:" + str(host_node_type_map) +
                "\n hosts:" + str(hosts) + "\n ceph_hosts:" + str(ceph_hosts))

    ret_val = False
    playbook_path_ceph_volume = consts.KUBERNETES_CEPH_VOL
    playbook_path_ceph_storage = consts.KUBERNETES_CEPH_STORAGE
    playbook_path_ceph_volume2 = consts.KUBERNETES_CEPH_VOL2
    playbook_path_ceph_volume_first = consts.KUBERNETES_CEPH_VOL_FIRST
    playbook_path_delete_secret = consts.KUBERNETES_CEPH_DELETE_SECRET
    playbook_path_ceph_deploy = consts.CEPH_DEPLOY
    playbook_path_ceph_mds = consts.CEPH_MDS
    playbook_path_ceph_deploy_admin = consts.CEPH_DEPLOY_ADMIN
    playbook_path_ceph_mon = consts.CEPH_MON
    PROXY_DATA_FILE = consts.PROXY_DATA_FILE
    VARIABLE_FILE = consts.VARIABLE_FILE
    SRC_PACKAGE_PATH = consts.INVENTORY_SOURCE_FOLDER
    for key, value in host_node_type_map.iteritems():
        node_type1 = value
        if node_type1 == "master":
            master_hostname = key
    if hosts:
        count = 0
        for i in range(len(hosts)):
            logger.info(playbook_path_delete_secret)
            node_type = hosts[i].get(consts.HOST).get(consts.NODE_TYPE)
            logger.info(node_type)
            if node_type == "master" and count == 0:
                count = count + 1
                ret_val = apbl.launch_ansible_playbook_delete_secret(
                    playbook_path_delete_secret, master_hostname,
                    PROXY_DATA_FILE)
                if not ret_val:
                    logger.error('FAILED IN INSTALLING FILE PLAY')
                    exit(1)
    if ceph_hosts:
        ceph_hostnamelist = __hostname_list(ceph_hosts)
        for i in range(len(ceph_hosts)):
            host_ip = ceph_hosts[i].get(consts.HOST).get(consts.IP)
            host_name = ceph_hosts[i].get(consts.HOST).get(consts.HOSTNAME)
            node_type = ceph_hosts[i].get(consts.HOST).get(consts.NODE_TYPE)
            ret_val = apbl.launch_ansible_playbook_ceph_volume_first(
                playbook_path_ceph_volume_first, host_name, SRC_PACKAGE_PATH,
                VARIABLE_FILE, PROXY_DATA_FILE, host_ip)
            if not ret_val:
                logger.error('FAILED IN INSTALLING FILE PLAY')
                exit(1)
            if node_type == "ceph_controller":
                ceph_controller_ip = ceph_hosts[i].get(consts.HOST).get(consts.IP)
                ceph_claims = ceph_hosts[i].get(consts.HOST).get(consts.CEPH_CLAIMS)
                logger.info('EXECUTING CEPH VOLUME PLAY')
                logger.info(playbook_path_ceph_volume)
                controller_host_name = host_name
                for i in range(len(ceph_hostnamelist)):
                    osd_host_name = ceph_hostnamelist[i]
                    user_id = ceph_hosts[i].get(consts.HOST).get(consts.USER)
                    passwd = ceph_hosts[i].get(consts.HOST).get(consts.PASSWORD)
                    osd_ip = ceph_hosts[i].get(consts.HOST).get(consts.IP)
                    ret_val = apbl.launch_ansible_playbook_ceph_volume(
                        playbook_path_ceph_volume, host_name, SRC_PACKAGE_PATH,
                        VARIABLE_FILE, PROXY_DATA_FILE, osd_host_name, user_id,
                        passwd, osd_ip)
                if not ret_val:
                    logger.error('FAILED IN INSTALLING FILE PLAY')
                    exit(1)
        for i in range(len(ceph_hostnamelist)):
            host_name = ceph_hostnamelist[i]
            user_id = ceph_hosts[i].get(consts.HOST).get(consts.USER)
            passwd = ceph_hosts[i].get(consts.HOST).get(consts.PASSWORD)
            logger.info(playbook_path_ceph_deploy)
            ret_val = apbl.launch_ansible_playbook_ceph_deploy(
                playbook_path_ceph_deploy, host_name, controller_host_name,
                VARIABLE_FILE, PROXY_DATA_FILE, user_id, passwd)
            if not ret_val:
                logger.error('FAILED IN INSTALLING FILE PLAY')
                exit(1)
        logger.info(playbook_path_ceph_mon)
        ret_val = apbl.launch_ansible_playbook_ceph_mon(playbook_path_ceph_mon,
                                                        controller_host_name,
                                                        VARIABLE_FILE,
                                                        PROXY_DATA_FILE)
        if not ret_val:
            logger.error('FAILED IN INSTALLING FILE PLAY')
            exit(1)
        for i in range(len(ceph_hosts)):
            host_ip = ceph_hosts[i].get(consts.HOST).get(consts.IP)
            host_name = ceph_hosts[i].get(consts.HOST).get(consts.HOSTNAME)
            node_type = ceph_hosts[i].get(consts.HOST).get(consts.NODE_TYPE)
            flag_second_storage = 0
            if node_type == "ceph_osd":
                flag_second_storage = 1
                second_storage = ceph_hosts[i].get(consts.HOST).get(consts.STORAGE_TYPE)
                logger.info("secondstorage is")
                if second_storage != None:
                    for i in range(len(second_storage)):
                        storage = second_storage[i]
                        logger.info('EXECUTING CEPH STORAGE PLAY')
                        logger.info(playbook_path_ceph_storage)
                        ret_val = apbl.launch_ansible_playbook_ceph_storage(
                            playbook_path_ceph_storage, host_name,
                            controller_host_name, SRC_PACKAGE_PATH,
                            VARIABLE_FILE, storage, PROXY_DATA_FILE, node_type)
                        if not ret_val:
                            logger.error('FAILED IN INSTALLING FILE PLAY')
                            exit(1)
        for i in range(len(ceph_hostnamelist)):
            host_name = ceph_hostnamelist[i]
            logger.info(playbook_path_ceph_deploy_admin)
            ret_val = apbl.launch_ansible_playbook_ceph_deploy_admin(
                playbook_path_ceph_deploy_admin, host_name,
                controller_host_name, VARIABLE_FILE, PROXY_DATA_FILE)
            if not ret_val:
                logger.error('FAILED IN INSTALLING FILE PLAY')
                exit(1)
        logger.info(playbook_path_ceph_mds)
        ret_val = apbl.launch_ansible_playbook_ceph_mon(
            playbook_path_ceph_mds, controller_host_name,
            VARIABLE_FILE, PROXY_DATA_FILE)
        if not ret_val:
            logger.error('FAILED IN INSTALLING FILE PLAY')
            exit(1)
    if hosts:
        count = 0
        for i in range(len(hosts)):
            node_type = hosts[i].get(consts.HOST).get(consts.NODE_TYPE)
            logger.info(node_type)
            if node_type == "master" and count == 0:
                count = count + 1  #changes for ha
                hostname = hosts[i].get(consts.HOST).get(consts.HOSTNAME)
                logger.info(playbook_path_ceph_volume2)
                logger.info("flag secondstorage is")
                logger.info(flag_second_storage)
                if flag_second_storage == 1:
                    ceph_claims = ceph_hosts[i].get(consts.HOST).get(consts.CEPH_CLAIMS)
                    for i in range(len(ceph_claims)):
                        ceph_claim_name = ceph_claims[i].get(
                            consts.CLAIM_PARAMETERS).get(consts.CEPH_CLAIM_NAME)
                        logger.info('ceph_claim name is %s', ceph_claim_name)
                        ceph_storage_size = ceph_claims[i].get(
                            consts.CLAIM_PARAMETERS).get(consts.CEPH_STORAGE)
                        logger.info('ceph_storage_size is %s', ceph_storage_size)
                        ret_val = apbl.launch_ansible_playbook_ceph_volume2(
                            playbook_path_ceph_volume2, hostname, SRC_PACKAGE_PATH,
                            VARIABLE_FILE, ceph_storage_size, ceph_claim_name,
                            PROXY_DATA_FILE, controller_host_name, ceph_controller_ip)
                        if not ret_val:
                            logger.error('FAILED IN INSTALLING FILE PLAY')
                            exit(1)
    logger.info('Exit')
    return ret_val

def launch_persitent_volume_kubernetes(host_name_map, host_node_type_map, hosts, persistent_vol):
    """
    This function is used for deploy the persistent_volume
    """
    logger.info("\n Argument List:" + "\n host_name_map:" + str(host_name_map) +
                "\n host_node_type_map:" + str(host_node_type_map) +
                "\n hosts:" + str(hosts) +
                "\n persistent_vol:" + str(persistent_vol))

    ret_val = False
    playbook_path_persistent_volume = consts.KUBERNETES_PERSISTENT_VOL
    VARIABLE_FILE = consts.VARIABLE_FILE
    PROXY_DATA_FILE = consts.PROXY_DATA_FILE
    SRC_PACKAGE_PATH = consts.INVENTORY_SOURCE_FOLDER
    count = 0
    for key, value in host_node_type_map.iteritems():
        node_type = value
        host_name = key
        if node_type == "master" and count == 0:
            for i in range(len(persistent_vol)):
                count = count + 1
                storage_size = persistent_vol[i].get(consts.CLAIM_PARAMETERS).get(consts.STORAGE)
                claim_name = persistent_vol[i].get(consts.CLAIM_PARAMETERS).get(consts.CLAIM_NAME)
                logger.info('EXECUTING PERSISTENT VOLUME PLAY')
                logger.info(playbook_path_persistent_volume)
                ret_val = apbl.launch_ansible_playbook_persistent_volume(
                    playbook_path_persistent_volume, host_name,
                    SRC_PACKAGE_PATH, VARIABLE_FILE, storage_size, claim_name,
                    PROXY_DATA_FILE)
                if not ret_val:
                    logger.error('FAILED IN INSTALLING FILE PLAY')
                    exit(1)
    logger.info('Exit')
    return ret_val

def get_host_master_name(Project_name):
    logger.info("\n Argument List:" + "\n Project_name:" + Project_name)

    VARIABLE_FILE = consts.VARIABLE_FILE
    config = file_utils.read_yaml(VARIABLE_FILE)
    project_path = config.get(consts.PROJECT_PATH)
    inventory_file_path = project_path + Project_name + "/inventory.cfg"
    logger.info('Inventory file path is %s', inventory_file_path)
    with open(inventory_file_path) as f:
        for line in f:
            if re.match("\[kube\-master\]", line):
                master_hostname1 = f.next()
                master_hostname = master_hostname1.strip(' \t\n\r')
                logger.info('master_hostname is %s', master_hostname)
    logger.info('Exit')
    return master_hostname


def get_hostname_ip_map_list(Project_name):
    logger.info("\n Argument List:" + "\n Project_name:" + Project_name)

    VARIABLE_FILE = consts.VARIABLE_FILE
    config = file_utils.read_yaml(VARIABLE_FILE)
    project_path = config.get(consts.PROJECT_PATH)
    inventory_file_path = project_path + Project_name + "/inventory.cfg"
    logger.info('Inventory file path is %s', inventory_file_path)
    hostname_map = {}
    with open(inventory_file_path) as f:
        for line in f:
            if "ansible_ssh_host=" in line:
                host_ip1 = line.split("ansible_ssh_host=", 1)[1]
                host_ip = host_ip1.strip(' \t\n\r')
                hostnamestringlist = line.split(" ")
                host_name = hostnamestringlist[0]
                host_name = host_name.strip(' \t\n\r')
                if host_ip:
                    if host_name:
                        hostname_map[host_name] = host_ip
    logger.info(' hostname_map is %s', str(hostname_map))
    logger.info('Exit')
    return hostname_map


def get_first_node_host_name(Project_name):
    logger.info("\n Argument List:" + "\n Project_name:" + Project_name)

    VARIABLE_FILE = consts.VARIABLE_FILE
    config = file_utils.read_yaml(VARIABLE_FILE)
    project_path = config.get(consts.PROJECT_PATH)
    inventory_file_path = project_path + Project_name + "/inventory.cfg"
    logger.info('Inventory file path is %s', inventory_file_path)
    with open(inventory_file_path) as f:
        for line in f:
            if re.match("\[kube\-node\]", line):
                node_hostname1 = f.next()
                node_hostname = node_hostname1.strip(' \t\n\r')
                logger.info('node_hostname is %s', node_hostname)
    logger.info('Exit')
    return node_hostname

class CpuPinningConfiguration(object):
    def __init__(self):
        pass

    def launch_cpu_pinning_kubernetes(self, config, PROXY_DATA_FILE, VARIABLE_FILE):
        logger.info("\n Argument List:" + "\n config:" + str(config) +
                    "\n PROXY_DATA_FILE:" + str(PROXY_DATA_FILE) +
                    "\n VARIABLE_FILE:" + str(VARIABLE_FILE))

        ret_val = False
        try:
            logger.info("launch_cpu_pinning_kubernetes")
            ret_val = apbl.launch_cpu_manager_configuration_play(
                consts.K8_CPU_PINNING_CONFIG, PROXY_DATA_FILE, VARIABLE_FILE)
        except:
            logger.error('CPU MANAGER CONFIGURATION FAILED ')
            ret_val = False

        logger.info('Exit')
        return ret_val
def enable_cluster_logging(value, Project_name, log_level, logging_port):
    """
    This function is used to enable logging in cluster
    :param value:- Check whether to enable logging or not
    :param project name:- Project name
    :return: True/False - True if successful otherwise return false
    """
    logger.info("\n Argument List:" + "\n value:" + value +
                "\n Project_name:" + Project_name +
                "\n log_level:" + log_level +
                "\n logging_port" + logging_port)

    logger.info('EXECUTING LOGGING ENABLE PLAY')
    logger.info(consts.K8_LOGGING_PLAY)
    ret_val = apbl.launch_ansible_playbook_enable_logging(
        consts.K8_LOGGING_PLAY, consts.PROXY_DATA_FILE, consts.VARIABLE_FILE,
        value, Project_name, log_level, consts.LOG_FILE_PATH, logging_port)

    logger.info('Exit')
    return ret_val


class KubectlConfiguration(KubectlPlayBookLauncher):
    def __init__(self):
        pass

    def install_kubectl(self, host_name_map, host_node_type_map, ha_enabled,
                        Project_name, config, VARIABLE_FILE, SRC_PACKAGE_PATH):
        """
        This function is used to install kubectl at bootstrap node
        """
        logger.info("\n Argument List:" + "\n host_name_map:" + str(host_name_map) +
                    "\n host_node_type_map:" + str(host_node_type_map) +
                    "\n ha_enabled:" + ha_enabled +
                    "\n Project_name:" + Project_name +
                    "\n VARIABLE_FILE:" + str(VARIABLE_FILE) +
                    "\n SRC_PACKAGE_PATH:" + SRC_PACKAGE_PATH)

        ret_val = False
        playbook_path_install_kubectl = consts.K8_KUBECTL_INSTALLATION
        PROXY_DATA_FILE = consts.PROXY_DATA_FILE
        logger.info('INSTALL KUBECTL')

        for key, value in host_node_type_map.iteritems():
            node_type = value
            host_name = key
            for key, value in host_name_map.iteritems():
                ip = value
                host_name1 = key
                if node_type == "master" and host_name1 == host_name:
                    master_ip = ip
                    master_host_name = host_name
                    logger.info(master_ip)
                    logger.info(master_host_name)
                    break

        lb_ip = "127.0.0.1"
        ha_configuration = config.get(consts.KUBERNETES).get(consts.HA_CONFIG)
        if ha_configuration:
            for ha_config_list_data in ha_configuration:
                lb_ip = ha_config_list_data.get(consts.HA_API_EXT_LB).get("ip")

        logger.info("Loadbalancer ip %s", lb_ip)

        try:
            logger.info(playbook_path_install_kubectl)
            ret_val = self.launch_ansible_playbook_install_kubectl(
                playbook_path_install_kubectl, master_ip, master_host_name,
                ha_enabled, Project_name, lb_ip, VARIABLE_FILE, SRC_PACKAGE_PATH,
                PROXY_DATA_FILE)
        except Exception as exception_v:
            logger.error('FAILED IN KUBECTL INSTALLTION')
            logger.error(exception_v)
            ret_val = False
            exit(1)

        logger.info('Exit')
        return ret_val

    def set_kubectl_context(self, Project_name, VARIABLE_FILE, SRC_PACKAGE_PATH):
        """
        This function is used to set kubectl context
        """
        logger.info("\n Argument List:" + "\n Project_name:" + Project_name +
                    "\n VARIABLE_FILE:" + str(VARIABLE_FILE) +
                    "\n SRC_PACKAGE_PATH:" + SRC_PACKAGE_PATH)

        ret_val = False
        playbook_path_set_kubectl_context = consts.K8_ENABLE_KUBECTL_CONTEXT
        PROXY_DATA_FILE = consts.PROXY_DATA_FILE

        logger.info('SET KUBECTL CONTEXT')
        try:
            logger.info(playbook_path_set_kubectl_context)
            ret_val = self.launch_ansible_playbook_set_kubectl_context(
                playbook_path_set_kubectl_context, Project_name,
                VARIABLE_FILE, SRC_PACKAGE_PATH, PROXY_DATA_FILE)
        except:
            logger.error('FAILED IN SETTING KUBECTL CONTEXT')
            ret_val = False
            exit(1)

        logger.info('Exit')
        return ret_val


class CleanUpMultusPlugins(CleanUpMultusPlayBookLauncher):
    def __init__(self):
        pass

    def delete_flannel_interfaces(self, host_name_map, host_node_type_map,
                                  hosts_data_dict, Project_name):
        """
        This function is used to delete flannel interfaces
        """
        logger.info("\n Argument List:" + "\n host_name_map:" + str(host_name_map) +
                    "\n host_node_type_map:" + str(host_node_type_map) +
                    "\n hosts_data_dict:" + str(hosts_data_dict) +
                    "\n Project_name:" + Project_name)

        ret_val = False
        playbook_path_conf_delete_flannel_intf = consts.K8_DELETE_FLANNEL_INTERFACE
        PROXY_DATA_FILE = consts.PROXY_DATA_FILE
        SRC_PACKAGE_PATH = consts.INVENTORY_SOURCE_FOLDER
        logger.info('EXECUTING FLANNEL INTERFACE DELETION PLAY')
        for item1 in hosts_data_dict:
            for key in item1:
                if key == "Multus_network":
                    multus_network = item1.get("Multus_network")
                    for item2 in multus_network:
                        for key in item2:
                            if key == "CNI_Configuration":
                                cni_configuration = item2.get("CNI_Configuration")
                                for item3 in cni_configuration:
                                    for key in item3:
                                        if consts.FLANNEL_NETWORK == key:
                                            all_hosts = item3.get(consts.FLANNEL_NETWORK)
                                            for host_data in all_hosts:
                                                hostdetails = host_data.get(consts.FLANNEL_NETWORK_DETAILS)
                                                networkName = hostdetails.get(consts.NETWORK_NAME)

        logger.info('networkName :%s', networkName)
        for key, value in host_node_type_map.iteritems():
            node_type = value
            host_name = key
            for key, value in host_name_map.iteritems():
                ip = value
                host_name1 = key
                if node_type == "master" and host_name1 == host_name:
                    master_ip = ip
                    master_host_name = host_name
                    logger.info('master_ip : %s', master_ip)
                    logger.info('master_host_name %s', master_host_name)
                    break

        try:
            logger.info('DELETING FLANNEL INTERFACE. Master ip - %s, '
                        'Master Host Name - %s' %(master_ip, master_host_name))
            logger.info(playbook_path_conf_delete_flannel_intf)
            node_type = "master"
            ret_val = self.launch_ansible_playbook_delete_flannel_interfaces(
                playbook_path_conf_delete_flannel_intf, master_ip,
                master_host_name, node_type, networkName, SRC_PACKAGE_PATH,
                PROXY_DATA_FILE)
        except:
            logger.error('FAILED IN DELETING FLANNEL INTERFACE')
            ret_val = False

        host_name_map_ip = get_hostname_ip_map_list(Project_name)
        for key, value in host_name_map_ip.iteritems():
            ip = value
            host_name = key
            if master_host_name != host_name:
                logger.info("clean up node ip: %s", ip)
                logger.info("clean up host name: %s", host_name)
                node_type = "minion"
                ret_val = self.launch_ansible_playbook_delete_flannel_interfaces(
                    playbook_path_conf_delete_flannel_intf, ip, host_name,
                    node_type, networkName, SRC_PACKAGE_PATH, PROXY_DATA_FILE)
                if not ret_val:
                    logger.error('FAILED IN DELETING FLANNEL INTERFACE')
                    exit(1)

        logger.info('Exit')
        return ret_val


#########delete weave interface############
    def delete_weave_interface(self, host_name_map, host_node_type_map,
                               hosts_data_dict, Project_name):
        """
        This function is used to delete weave interface
        """
        logger.info("\n Argument List:" + "\n host_name_map:" + str(host_name_map) +
                    "\n host_node_type_map:" + str(host_node_type_map) +
                    "\n hosts_data_dict:" + str(hosts_data_dict) +
                    "\n Project_name:" + Project_name)

        playbook_path_conf_delete_weave_intf = consts.K8_DELETE_WEAVE_INTERFACE
        PROXY_DATA_FILE = consts.PROXY_DATA_FILE
        SRC_PACKAGE_PATH = consts.INVENTORY_SOURCE_FOLDER
        logger.info('EXECUTING WEAVE INTERFACE DELETION PLAY')
        for item1 in hosts_data_dict:
            for key in item1:
                if key == "Multus_network":
                    multus_network = item1.get("Multus_network")
                    for item2 in multus_network:
                        for key in item2:
                            if key == "CNI_Configuration":
                                cni_configuration = item2.get("CNI_Configuration")
                                for item3 in cni_configuration:
                                    for key in item3:
                                        if consts.WEAVE_NETWORK == key:
                                            weave_network = item3.get(consts.WEAVE_NETWORK)
                                            for item1 in weave_network:
                                                weave_network1 = item1.get(consts.WEAVE_NETWORK_DETAILS)
                                                networkName = weave_network1.get(consts.NETWORK_NAME)
                                                logger.info('networkName is %s', networkName)

        for key, value in host_node_type_map.iteritems():
            node_type = value
            host_name = key
            logger.info(playbook_path_conf_delete_weave_intf)
            for key, value in host_name_map.iteritems():
                ip = value
                host_name1 = key
                if node_type == "master" and host_name1 == host_name:
                    master_ip = ip
                    master_host_name = host_name
                    logger.info('master_ip is %s', master_ip)
                    logger.info('master_host_name is %s', master_host_name)
                    hostname_master = host_name1
                    break

        node_type = "master"
        logger.info('DELETING WEAVE INTERFACE.. Master ip: ' + ip + \
                     ', Master Host Name:' + host_name)
        ret_val = self.launch_ansible_playbook_delete_weave_interface(
            playbook_path_conf_delete_weave_intf, master_ip, master_host_name,
            node_type, networkName, SRC_PACKAGE_PATH, PROXY_DATA_FILE)
        if not ret_val:
            logger.error('FAILED IN DELETING WEAVE INTERFACE')

        host_name_map_ip = get_hostname_ip_map_list(Project_name)
        for key, value in host_name_map_ip.iteritems():
            ip = value
            host_name = key
            if hostname_master != host_name:
                logger.info('clean up node ip is %s', ip)
                logger.info('clean up host name is %s', host_name)
                node_type = "minion"
                ret_val = self.launch_ansible_playbook_delete_weave_interface(
                    playbook_path_conf_delete_weave_intf, ip, host_name, node_type,
                    networkName, SRC_PACKAGE_PATH, PROXY_DATA_FILE)
                if not ret_val:
                    logger.error('FAILED IN DELETING WEAVE INTERFACE')

        logger.info('Exit')
        return ret_val

#########delete default weave interface############
    def delete_default_weave_interface(self, host_name_map, host_node_type_map,
                                       hosts_data_dict, Project_name):
        """
        This function is used to delete default weave interface
        """
        logger.info("\n Argument List:" + "\n host_name_map:" + str(host_name_map) +
                    "\n host_node_type_map:" + str(host_node_type_map) +
                    "\n hosts_data_dict:" + str(hosts_data_dict) +
                    "\n Project_name:" + Project_name)

        ret_val = False
        playbook_path_conf_delete_weave_intf = consts.K8_DELETE_WEAVE_INTERFACE
        PROXY_DATA_FILE = consts.PROXY_DATA_FILE
        SRC_PACKAGE_PATH = consts.INVENTORY_SOURCE_FOLDER
        logger.info('EXECUTING DEFAULT WEAVE INTERFACE DELETION PLAY')
        for item1 in hosts_data_dict:
            for key in item1:
                if key == "Default_Network":
                    default_network = item1.get("Default_Network")
                    if default_network:
                        networking_plugin = default_network.get(consts.NETWORKING_PLUGIN)
                        networkName = default_network.get(consts.NETWORK_NAME)
                        logger.info('networkName is %s', networkName)

        if networking_plugin != "weave":
            logger.info('DEFAULT NETWORKING PLUGIN IS NOT WEAVE, NO NEED TO CLEAN WEAVE')
            ret_val = True
            return ret_val

        for key, value in host_node_type_map.iteritems():
            node_type = value
            host_name = key
            logger.info(playbook_path_conf_delete_weave_intf)
            for key, value in host_name_map.iteritems():
                ip = value
                host_name1 = key
                if node_type == "master" and host_name1 == host_name:
                    master_ip = ip
                    master_host_name = host_name
                    logger.info('master_ip is %s', master_ip)
                    logger.info('master_host_name is %s', master_host_name)
                    break

        node_type = "master"
        ret_val = self.launch_ansible_playbook_delete_weave_interface(
            playbook_path_conf_delete_weave_intf, master_ip, master_host_name,
            node_type, networkName, SRC_PACKAGE_PATH, PROXY_DATA_FILE)
        if not ret_val:
            logger.error('FAILED IN DELETING DEFAULT WEAVE INTERFACE')

        host_name_map_ip = get_hostname_ip_map_list(Project_name)
        for key, value in host_name_map_ip.iteritems():
            ip = value
            host_name = key
            if master_host_name != host_name:
                logger.info('clean up node ip is %s', ip)
                logger.info('clean up host name is %s', host_name)
                node_type = "minion"
                ret_val = self.launch_ansible_playbook_delete_weave_interface(
                    playbook_path_conf_delete_weave_intf, ip, host_name, node_type,
                    networkName, SRC_PACKAGE_PATH, PROXY_DATA_FILE)
                if not ret_val:
                    logger.error('FAILED IN DELETING WEAVE INTERFACE')

        logger.info('Exit')
        return ret_val

    def clean_up_weave_dynamic_node(self, dynamic_hostname_map, dynamic_host_node_type_map):
        """
        This function is used to delete weave interface at dynamic node
        """
        logger.info("\n Argument List:" + "\n dynamic_hostname_map:" + str(dynamic_hostname_map) +
                    "\n dynamic_host_node_type_map:" + str(dynamic_host_node_type_map))

        ret_val = False
        playbook_path_conf_delete_weave_intf = consts.K8_DELETE_WEAVE_INTERFACE_DYNAMIC_NODE
        SRC_PACKAGE_PATH = consts.INVENTORY_SOURCE_FOLDER
        logger.info('EXECUTING WEAVE INTERFACE DELETION PLAY AT DYNAMIC NODE')
        logger.debug(dynamic_host_node_type_map)
        for key, value in dynamic_hostname_map.iteritems():
            ip = value
            host_name = key
            logger.info('IP is %s', ip)
            logger.info('Hostname is %s', host_name)
            logger.info(playbook_path_conf_delete_weave_intf)
            ret_val = self.launch_ansible_playbook_dynamic_node_weave_clean_up(
                playbook_path_conf_delete_weave_intf, ip, host_name,
                SRC_PACKAGE_PATH)
            if not ret_val:
                logger.error('FAILED IN DELETING WEAVE INTERFACE AT DYNAMIC NODE')

        logger.info('Exit')
        return ret_val


class MultusNetworkingPluginsConfiguration(object):
    def __init__(self):
        pass

    def launch_sriov_cni_configuration_cli(self, hosts_data_dict, Project_name):
        """
        This function is used to launch sriov cni
        """
        logger.info("\n Argument List:" + "\n hosts_data_dict:" + str(hosts_data_dict) +
                    "\n Project_name:" + Project_name)

        ret_hosts = False
        playbook_path_sriov_build_cni = consts.K8_SRIOV_CNI_BUILD
        playbook_path_sriov_dpdk_cni = consts.K8_SRIOV_DPDK_CNI
        playbook_path_sriov_dpdk_cni_bin_inst = consts.K8_SRIOV_DPDK_CNI_BIN_INST
        playbook_path_dpdk_driver_load = consts.K8_SRIOV_DPDK_DRIVER_LOAD
        playbook_path_sriov_cni_bin_inst = consts.K8_SRIOV_CNI_BIN_INST
        playbook_path_sriov_cni_enable = consts.K8_SRIOV_ENABLE
        playbook_path_sriov_configuration_script = consts.K8_SRIOV_CONFIG_SCRIPT
        PROXY_DATA_FILE = consts.PROXY_DATA_FILE
        SRC_PACKAGE_PATH = consts.K8_SOURCE_PATH
        CURRENT_DIR = consts.CWD
        minion_list = []
        dpdk_enable = "no"
        VARIABLE_FILE = consts.VARIABLE_FILE
        config = file_utils.read_yaml(VARIABLE_FILE)
        project_path = config.get(consts.PROJECT_PATH)
        inventory_file_path = project_path + Project_name + "/k8s-cluster.yml"

        logger.info('EXECUTING SRIOV CNI PLAY')
        logger.info("Inventory file path is %s", inventory_file_path)
        with open(inventory_file_path) as f:
            for line in f:
                if "kube_network_plugin:" in line:
                    network_plugin1 = line.split("kube_network_plugin:", 1)[1]
                    networking_plugin = network_plugin1.strip(' \t\n\r')
                    hostnamestringlist = line.split(" ")
                    networkPluginName = hostnamestringlist[0]
                    networkPluginName = networkPluginName.strip(' \t\n\r')
                    logger.info("Network plugin is %s", networking_plugin)

        for node in hosts_data_dict:
            for key in node:
                logger.info("Node is %s", node)
                if key == "Sriov":
                    all_hosts = node.get("Sriov")
                    logger.info("all hosts are %s", str(all_hosts))
                    for host_data in all_hosts:
                        logger.info("host_data are %s", str(host_data))
                        hostdetails = host_data.get("host")
                        hostname = hostdetails.get("hostname")
                        networks = hostdetails.get("networks")
                        logger.info("hostname is %s", str(hostname))
                        minion_list.append(hostname)
                        for network in networks:
                            dpdk_driver = 'vfio-pci'
                            dpdk_enable = network.get("dpdk_enable")
                            sriov_intf = network.get("sriov_intf")
                            logger.info("SRIOV CONFIGURATION ON NODES")
                            ret_hosts = apbl.launch_ansible_playbook_enable_sriov(
                                playbook_path_sriov_cni_enable, hostname, sriov_intf,
                                playbook_path_sriov_configuration_script, networking_plugin)

        ret_hosts = apbl.launch_ansible_playbook_build_sriov(
            playbook_path_sriov_build_cni, SRC_PACKAGE_PATH, PROXY_DATA_FILE)
        logger.info("DPDK Flag is %s", dpdk_enable)
        if dpdk_enable == "yes":
            ret_hosts = apbl.launch_ansible_playbook_build_sriov_dpdk(
                playbook_path_sriov_dpdk_cni, SRC_PACKAGE_PATH, PROXY_DATA_FILE)
        host_name = get_host_master_name(Project_name)
        logger.info("Executing for master %s", str(host_name))
        logger.info("INSTALLING SRIOV BIN ON MASTER")
        ret_hosts = apbl.launch_ansible_playbook_sriov_install(
            playbook_path_sriov_cni_bin_inst, host_name, SRC_PACKAGE_PATH)
        if dpdk_enable == "yes":
            logger.info("INSTALLING SRIOV DPDK BIN ON MASTER")
            ret_hosts = apbl.launch_ansible_playbook_sriov_dpdk_install(
                playbook_path_sriov_dpdk_cni_bin_inst, host_name, SRC_PACKAGE_PATH)

        for  host_name in minion_list:
            logger.info("executing for  minion %s", str(host_name))
            logger.info("INSTALLING SRIOV BIN ON WORKERS")
            ret_hosts = apbl.launch_ansible_playbook_sriov_install(
                playbook_path_sriov_cni_bin_inst, host_name, SRC_PACKAGE_PATH)
            if dpdk_enable == "yes":
                logger.info("INSTALLING SRIOV DPDK BIN ON WORKERS")
                ret_hosts = apbl.launch_ansible_playbook_dpdk_driver_load(
                    playbook_path_dpdk_driver_load, host_name, dpdk_driver)
                ret_hosts = apbl.launch_ansible_playbook_sriov_dpdk_install(
                    playbook_path_sriov_dpdk_cni_bin_inst, host_name, SRC_PACKAGE_PATH)
        logger.info('Exit')
        return ret_hosts

    def launch_sriov_network_creation_cli(self, hosts_data_dict, Project_name):
        """
        This function is used to create sriov network
        """
        logger.info("\n Argument List:" + "\n hosts_data_dict:" + str(hosts_data_dict) +
                    "\n Project_name:" + Project_name)

        ret_hosts = False
        playbook_path_cr_sriov_nw = consts.K8_SRIOV_CR_NW
        dpdk_enable = "no"
        playbook_path_cr_sriov_dpdk_nw = consts.K8_SRIOV_DPDK_CR_NW
        playbook_path_cr_sriov_dhcp_nw = consts.K8_SRIOV_DHCP_CR_NW
        playbook_path_sriov_conf = consts.K8_SRIOV_CONF
        PROXY_DATA_FILE = consts.PROXY_DATA_FILE

        masterHost = get_host_master_name(Project_name)
        logger.info("Performing config for node %s", str(masterHost))
        for node in hosts_data_dict:
            for key in node:
                for key in node:
                    if key == "Sriov":
                        all_hosts = node.get("Sriov")
                        for host_data in all_hosts:
                            hostdetails = host_data.get("host")
                            networks = hostdetails.get("networks")
                            node_hostname = hostdetails.get("hostname")
                            for network in networks:
                                dpdk_tool = '/etc/cni/scripts/dpdk-devbind.py'
                                dpdk_driver = 'vfio-pci'
                                dpdk_enable = network.get("dpdk_enable")
                                rangeEnd = network.get("rangeEnd")
                                rangeStart = network.get("rangeStart")
                                host = network.get("type")
                                sriov_gateway = network.get("sriov_gateway")
                                sriov_intf = network.get("sriov_intf")
                                sriov_subnet = network.get("sriov_subnet")
                                sriov_nw_name = network.get("network_name")
                                masterPlugin = network.get(consts.MASTER_PLUGIN)
                                logger.info("master host is %s", masterHost)
                                logger.info("node_hostname %s", node_hostname)
                                logger.info("dpdk_tool %s", dpdk_tool)
                                logger.info("dpdk_driver %s", dpdk_driver)
                                logger.info("dpdk_enable %s", dpdk_enable)
                                logger.info("sriov_intf %s", sriov_intf)
                                logger.info("masterHost %s", masterHost)
                                logger.info("sriov_nw_name %s", sriov_nw_name)
                                logger.info("rangeStart %s", rangeStart)
                                logger.info("rangeEnd %s", rangeEnd)
                                logger.info("sriov_subnet %s", sriov_subnet)
                                logger.info("sriov_gateway %s", sriov_gateway)
                                if dpdk_enable == "yes":
                                    logger.info("SRIOV NETWORK CREATION STARTED USING DPDK DRIVER")
                                    ret_hosts = apbl.launch_ansible_playbook_sriov_dpdk_crd_nw(
                                        playbook_path_cr_sriov_dpdk_nw, playbook_path_sriov_conf,
                                        sriov_intf, masterHost, sriov_nw_name, dpdk_driver,
                                        dpdk_tool, node_hostname, masterPlugin)

                                if dpdk_enable == "no":
                                    if host == "host-local":
                                        logger.info("SRIOV NETWORK CREATION STARTED USING KERNEL " +
                                                    "DRIVER WITH IPAM host-local")
                                        ret_hosts = apbl.launch_ansible_playbook_sriov_crd_nw(
                                            playbook_path_cr_sriov_nw, playbook_path_sriov_conf,
                                            sriov_intf, masterHost, sriov_nw_name, rangeStart,
                                            rangeEnd, sriov_subnet, sriov_gateway, masterPlugin)

                                    if host == "dhcp":
                                        logger.info("SRIOV NETWORK CREATION STARTED USING " +
                                                    "KERNEL DRIVER WITH IPAM host-dhcp")
                                        ret_hosts = apbl.launch_ansible_playbook_sriov_dhcp_crd_nw(
                                            playbook_path_cr_sriov_dhcp_nw, playbook_path_sriov_conf,
                                            sriov_intf, masterHost, sriov_nw_name, PROXY_DATA_FILE)


        logger.info('Exit')
        return ret_hosts


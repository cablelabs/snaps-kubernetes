###########################################################################
# Copyright 2017 ARICENT HOLDINGS LUXEMBOURG SARL. and
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


"""
Purpose : kubernetes Provisioning
Date :27/12/2017
Created By :Aricent
"""
import logging
import re
import subprocess
import time
import os
from pathlib import Path
from shutil import copyfile
import netaddr

from snaps_k8s.common.utils import file_utils
from snaps_k8s.common.consts import consts
from snaps_k8s.ansible_p.ansible_utils import ansible_configuration as aconf
from snaps_k8s.ansible_p.ansible_utils.ansible_configuration import KubectlConfiguration
from snaps_k8s.ansible_p.ansible_utils.ansible_configuration import CleanUpMultusPlugins
from snaps_k8s.ansible_p.ansible_utils.ansible_configuration import MultusNetworkingPluginsConfiguration
from snaps_k8s.ansible_p.ansible_utils import ansible_playbook_launcher

logger = logging.getLogger('deploy_venv')

def execute(config, operation, deploy_file):
    logger.info("\n Argument List:" + "\n config:" + str(config) +
                "\n operation:" + operation + "\n deploy_file:" + deploy_file)

    ret = False
    if not config:
        return

    logger.info('Host entries')
    hosts = config.get(consts.KUBERNETES).get(consts.HOSTS)
    __add_ansible_hosts(hosts)
    proxy_dic = __create_proxy_dic(config)
    logger.info('PROXY - %s', proxy_dic)
    logger.info('Deploy File - %s', deploy_file)
    ret = aconf.provision_preparation(proxy_dic, "False")
    if not ret:
        logger.error('FAILED IN SET PROXY')
        exit(1)

    logger.info('enable ssh key')
    hosts = config.get(consts.KUBERNETES).get(consts.HOSTS)
    __enable_key_ssh(hosts)
    hostname_map = get_hostname_map(hosts)
    host_node_type_map = __create_host_nodetype_map(hosts)
    hosts_data_dict = get_sriov_nw_data(config)
    host_port_map = __create_host_port_map(hosts)
    loadbalancer_dict = None
    ha_enabled = "False"

    # duplicate ip check start
    networks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
    default_network_items = __get_network_item(
        networks, "Default_Network").get("Default_Network")
    multus_network = get_multus_network(networks).get("Multus_network")
    multus_cni = get_multus_network_elements(multus_network, "CNI")
    multus_cni_configuration = get_multus_network_elements(
        multus_network, "CNI_Configuration")
    if multus_cni:
        range_network_list = __get_net_ip_range(
            hostname_map=hostname_map, multus_cni=multus_cni,
            networks=multus_cni_configuration,
            default_network_items=default_network_items)
        ret = __validate_net_ip_range(range_network_list[0],
                                      range_network_list[1],
                                      range_network_list[2])
        if not ret:
            logger.error(
                'VALIDATION FAILED IN NETWORK CONFIGURATION: '
                'OVERLAPPING IPS ARE FOUND')
            exit(1)

    logger.info("PROVISION_PREPARATION AND DEPLOY METHOD CALLED")
    Networks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
    logger.info(Networks)
    for item1 in Networks:
        for key in item1:
            if key == "Default_Network":
                default_network = item1.get(consts.DEFAULT_NETWORK)
                if default_network:
                    service_subnet = default_network.get(consts.SERVICE_SUBNET)
                    logger.info("Service subnet = %s", service_subnet)
                    pod_subnet = default_network.get(consts.POD_SUBNET)
                    logger.info("pod_subnet = %s", pod_subnet)
                    networking_plugin = default_network.get(
                        consts.NETWORKING_PLUGIN)
                    logger.info("networking_plugin = %s", networking_plugin)

    docker_repo = config.get(consts.KUBERNETES).get(consts.DOCKER_REPO)
    if docker_repo:
        docker_ip = docker_repo.get(consts.IP)
        docker_user = docker_repo.get(consts.USER)
        docker_pass = docker_repo.get(consts.PASSWORD)
        logger.info('Enable ssh key')
        __pushing_key(docker_ip, docker_user, docker_pass)

    hosts = config.get(consts.KUBERNETES).get(consts.HOSTS)
    Project_name = config.get(consts.KUBERNETES).get(consts.PROJECT_NAME)
    logger.info('Project Name is %s', Project_name)
    Git_branch = config.get(consts.KUBERNETES).get(consts.GIT_BRANCH)
    logger.info('Git Branch Name is %s', Git_branch)
    ret = aconf.launch_provisioning_kubernetes(hostname_map, host_node_type_map,
                                               host_port_map, service_subnet,
                                               pod_subnet, networking_plugin,
                                               docker_repo, hosts, Git_branch,
                                               Project_name, config, ha_enabled,
                                               loadbalancer_dict=loadbalancer_dict)
    if not ret:
        logger.error('FAILED IN DEPLOY')
        exit(1)
    else:
        ret = create_backup_deploy_conf(config, deploy_file)
        if not ret:
            logger.error('FAILED IN CREATING DEPLOY BACKUP')
            exit(1)

    logger.info("cephhost creation")
    ceph_hosts = config.get(consts.KUBERNETES).get(
        consts.PERSISTENT_VOLUME).get(consts.CEPH_VOLUME)
    if ceph_hosts:
        __add_ansible_hosts(ceph_hosts)
        logger.info("enable ssh key for ceph IPs")
        __enable_key_ssh(ceph_hosts)
        ret = aconf.launch_ceph_kubernetes(hostname_map, host_node_type_map,
                                           hosts, ceph_hosts)
        if not ret:
            logger.error('FAILED IN CEPH DEPLOY')
            exit(1)
    logger.info('Persistent host volume Start')
    persistent_vol = config.get(consts.KUBERNETES).get(
        consts.PERSISTENT_VOLUME).get(consts.HOST_VOL)
    if persistent_vol:
        ret = aconf.launch_persitent_volume_kubernetes(hostname_map,
                                                       host_node_type_map,
                                                       hosts, persistent_vol)
        if not ret:
            logger.error('FAILED IN DEPLOY')
            exit(1)

    logger.info("Additional N/W plugins multus_cni installation")
    multus_cni_installed = False
    multus_enabled = get_multus_cni_value(config)
    logger.info('multus_enabled value: %s', multus_enabled)

    macvlan_cni = get_macvlan_value(config)
    logger.info('macvlan value: %s', macvlan_cni)

    dhcp_cni = get_dhcp_value(config)
    logger.info('dhcp value: %s', dhcp_cni)

    if multus_enabled:
        logger.info('crdNetwork creation')
        time.sleep(10)
        ret = aconf.launch_crd_network(hostname_map, host_node_type_map)
        if not ret:
            logger.error('FAILED IN CRD CREATION')
            exit(1)

        ret = aconf.launch_multus_cni(hostname_map, host_node_type_map,
                                      service_subnet, pod_subnet,
                                      networking_plugin)
        if not ret:
            logger.error('FAILED IN MULTUS CONFIGURATION')
            exit(1)

        logger.info('MULTUS CONFIGURED SUCCESSFULLY.. NOW CREATING '
                    'DEFAULT PLUGIN NETWORK')
        multus_cni_installed = True
        if networking_plugin != "none":
            ret = __create_default_network_multus(config, hostname_map,
                                                  host_node_type_map,
                                                  service_subnet, pod_subnet,
                                                  networking_plugin)
            if ret:
                logger.info('SUCCESSFULLY CREATED DEFAULT NETWORK')
            else:
                logger.error('FAILED IN CREATING DEFAULT NETWORK')

        networks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
        multus_network = get_multus_network(networks).get("Multus_network")
        multus_cni = get_multus_network_elements(multus_network, "CNI")
        logger.info('multus_cni: %s', multus_cni)
        for cni in multus_cni:
            logger.info('multus_cni_installed: %s', multus_cni_installed)
            logger.info('cni: %s', cni)
            if multus_cni_installed:
                if cni == "dhcp":
                    logger.info('DHCP Network Plugin')
                    if multus_cni_installed:
                        if dhcp_cni:
                            logger.info('CONFIGURING DHCP')
                            MultusNetworkingPluginsAddition().dhcp_installation(config)
                        else:
                            logger.info(
                                'DHCP CONFIGURATION  EXIT , '
                                'REASON--> DHCP  IS DISABLED ')
                elif cni == "sriov":
                    logger.info('Sriov Network Plugin')
                    Project_name = config.get(consts.KUBERNETES).get(
                        consts.PROJECT_NAME)
                    if hosts_data_dict != '':
                        ret = aconf.launch_sriov_cni_configuration(
                            hostname_map, host_node_type_map, hosts_data_dict,
                            Project_name)
                        ret = aconf.launch_sriov_network_creation(
                            hostname_map, host_node_type_map, hosts_data_dict,
                            Project_name)
                        if not ret:
                            logger.error('FAILED IN SRIOV NW Creation')
                    else:
                        logger.info('Config data for SRIOV network is incomplete ')
                elif cni == consts.FLANNEL:
                    logger.info('Flannel Network Plugin')
                    ret = launch_flannel_interface(config, hostname_map,
                                                   host_node_type_map,
                                                   networking_plugin,
                                                   Project_name)
                    if not ret:
                        logger.error(
                            'FAILED IN FLANNEL INTERFACE CREATION')
                elif cni == consts.WEAVE:
                    logger.info('Weave Network Plugin')
                    ret = __launch_weave_interface(config, hostname_map,
                                                   host_node_type_map,
                                                   service_subnet,
                                                   pod_subnet,
                                                   networking_plugin)
                    if not ret:
                        logger.error('FAILED IN WEAVE INTERFACFE CREATION')
                elif cni == "macvlan":
                    logger.info('Macvlan Network Plugin')
                    if multus_cni_installed:
                        if macvlan_cni:
                            logger.info('CONFIGURING MAC-VLAN')
                            __macvlan_installation(config)
                        else:
                            logger.info(
                                'MAC-VLAN CONFIGURATION  EXIT , '
                                'REASON--> MACVLAN  IS DISABLED ')

            else:
                logger.info('MULTUS CNI INSTALLTION FAILED')
    else:
        logger.info('MULTUS CNI IS DISABLED')

    if multus_cni_installed:
        time.sleep(100)
        ret = aconf.delete_existing_conf_files_after_additional_plugins(
            hostname_map, host_node_type_map, networking_plugin)
        if not ret:
            logger.error('FAILED IN DELETING EXISTING CONF FILE')
            exit(1)

    logger.info('Enabling Authentication')
    basic_authentication = config.get(consts.KUBERNETES).get(
        consts.BASIC_AUTHENTICATION)
    ret = __enabling_basic_authentication(basic_authentication,
                                          Project_name)
    if not ret:
        logger.error('FAILED IN DEPLOY')
        exit(1)

    logger.info("etcd changes")
    ret = _modifying_etcd_node(Project_name, hostname_map, host_node_type_map)
    if not ret:
        logger.error('FAILED IN DEPLOY')
        exit(1)

    logger.info('Metrics Server')
    metrics_server = config.get(consts.KUBERNETES).get(
        consts.METRICS_SERVER)
    if metrics_server:
        logger.info('Metrics server configuration')
        ret = aconf.launch_metrics_server(
            hostname_map, host_node_type_map)
    logger.info('Exit')
    return ret


def ip_var_args(*argv):
    logger.info("\n Argument List:" + "\n argv:" + str(argv))

    if len(argv) % 2:
        logger.error("Invalid configuration")
        exit(1)

    for i in range(len(argv)):
        if i % 2:
            continue

        start_ip = int(netaddr.IPAddress(argv[i]))
        end_ip = int(netaddr.IPAddress(argv[i + 1]))
        for j in range(len(argv)):
            if j % 2:
                continue
            if i == j:
                continue
            if int(netaddr.IPAddress(argv[j])) <= start_ip <= int(
                    netaddr.IPAddress(argv[j + 1])) or int(
                        netaddr.IPAddress(argv[j])) <= end_ip <= int(
                            netaddr.IPAddress(argv[j + 1])):
                logger.error('Alert ! IPs ranges are intermingled')
                logger.info('Exit')
                return False

        logger.info('Exit')
        return True

def __get_network_item(networks, network_list_item):
    logger.info("\n Argument List:" + "\n networks" + str(networks) +
                "\n network_list_item" + network_list_item)
    for network_item in networks:
        for key in network_item:
            if key == network_list_item:
                logger.info('Exit')
                return network_item
    logger.info('Exit')

def __validate_net_ip_range(net_names, range_start_dict, range_end_dict):
    logger.info("\n Argument List:" + "\n net_names:" +
                str(net_names) + "\n range_start_dict:" +
                str(range_start_dict) + "\n range_end_dict:" + str(range_end_dict))
    ret = True
    __check_dup_start_end_ip(net_names, range_start_dict)
    __check_dup_start_end_ip(net_names, range_end_dict)
    count = 0
    length_of_elements = len(net_names)
    while count < int(length_of_elements):
        count1 = count + 1
        while count1 < int(length_of_elements):
            if not ip_var_args(
                    range_start_dict.get(net_names[count]),
                    range_end_dict.get(net_names[count]),
                    range_start_dict.get(net_names[count1]),
                    range_end_dict.get(net_names[count1])):
                return False
            count1 = count1 + 1
        count = count + 1
    logger.info('Exit')
    return ret


def __check_dup_start_end_ip(net_names, range_dict):
    logger.info("\n Argument List:" + "\n net_names:" +
                str(net_names) + "\n range_dict:" + str(range_dict))
    final_list = []
    for network in net_names:
        if range_dict.get(network) not in final_list:
            final_list.append(range_dict.get(network))
        else:
            logger.error("duplicate network name found - %s with ip %s",
                         network, range_dict.get(network))
            logger.info('Exit')
            return False
    logger.info('Exit')
    return True

def get_multus_network(networks):
    logger.info("\n Argument List:" + "\n networks:" + str(networks))
    for network_item in networks:
        for key in network_item:
            if key == "Multus_network":
                logger.info('Exit')
                return network_item
    logger.info('Exit')

def get_multus_network_elements(multus_network, element):
    logger.info("\n Argument List:" + "\n multus_network:" +
                str(multus_network) + "\n element:" + str(element))
    for item in multus_network:
        for key in item:
            if key == element:
                logger.info('Exit')
                return item[key]
    logger.info('Exit')

def __network_dict(networks, net_type):
    logger.info("\n Argument List:" + "\n networks:" + str(networks) +
                "\n net_type:" + net_type)
    for network in networks:
        for key in network:
            if key == net_type:
                logger.info('Exit')
                return network.get(net_type)
    logger.info('Exit')

def __get_net_ip_range(**kargs):
    logger.info("\n Argument List:" + "\n kargs:" + str(kargs))
    multus_cni = kargs.get("multus_cni")
    networks = kargs.get("networks")
    default_network_items = kargs.get("default_network_items")
    start_range_dict = {}
    end_range_dict = {}
    network_name_list = []
    default_cni_plugin = default_network_items.get("networking_plugin")

    if default_cni_plugin is None:
        start_range_dict = {}
        end_range_dict = {}
        network_name_list = []

    for cni in multus_cni:
        if cni == "sriov":
            for host in __network_dict(networks, "Sriov"):
                for key in host:
                    for network_item in host.get(key).get('networks'):
                        if network_item.get("type") == "host-local":
                            start_range_dict[network_item.get(
                                "network_name")] = network_item.get("rangeStart")
                            end_range_dict[network_item.get(
                                "network_name")] = network_item.get("rangeEnd")
                            network_name_list.append(
                                network_item.get("network_name"))

        elif cni == "macvlan":
            for macvlan_network in __network_dict(networks, "Macvlan"):
                if macvlan_network.get("macvlan_networks").get(
                        "type") == "host-local":
                    start_range_dict[
                        macvlan_network.get("macvlan_networks").get(
                            "network_name")] = macvlan_network.get(
                                "macvlan_networks").get("rangeStart")
                    end_range_dict[macvlan_network.get("macvlan_networks").get(
                        "network_name")] = macvlan_network.get(
                            "macvlan_networks").get("rangeEnd")
                    network_name_list.append(macvlan_network.get(
                        "macvlan_networks").get("network_name"))
        logger.info('Exit')
        return network_name_list, start_range_dict, end_range_dict
def get_cluster_hostname(Project_name):
    logger.info("\n Argument List:" + "\n Project_name:" + Project_name)
    config = file_utils.read_yaml(consts.VARIABLE_FILE)
    project_path = config.get(consts.PROJECT_PATH)
    inventory_file_path = project_path + Project_name + "/inventory.cfg"
    logger.info('Inventory file path get_master_ip function is %s', inventory_file_path)
    host_name_dict = {}
    with open(inventory_file_path) as f:
        for line in f:
            if "ansible_ssh_host=" in line:
                host_ip1 = line.split("ansible_ssh_host=", 1)[1]
                host_ip = host_ip1.strip(' \t\n\r')
                hostnamestringlist = line.split(" ")
                host_name = hostnamestringlist[0]
                host_name = host_name.strip(' \t\n\r')
                host_name_dict[host_name] = host_ip

    return host_name_dict

def clean_k8(config, operation):
    """
    This method is used for cleanup of kubernetes cluster
    :param config :input configuration file
    :return ret :t/f
    """
    logger.info("\n Argument List:" + "\n config:" + str(config) +
                "\n operation:" + operation)

    ret = False
    if config:
        logger.info("Host entries in /etc/ansible/host file")
        hosts = config.get(consts.KUBERNETES).get(consts.HOSTS)
        __add_ansible_hosts(hosts)
        __enable_key_ssh(hosts)
        logger.info("Host name map")
        hostname_map = get_hostname_map(hosts)
        host_node_type_map = __create_host_nodetype_map(hosts)
        Git_branch = config.get(consts.KUBERNETES).get(consts.GIT_BRANCH)
        logger.info('Git Branch Name is %s', Git_branch)
        Project_name = config.get(consts.KUBERNETES).get(consts.PROJECT_NAME)
        logger.info('Project Name is %s', Project_name)
        VARIABLE_FILE = consts.VARIABLE_FILE
        SRC_PACKAGE_PATH = consts.INVENTORY_SOURCE_FOLDER
        multus_enabled = get_multus_cni_value_for_dynamic_node(config)
        logger.info('multus_enabled :%s', multus_enabled)

        logger.info("Set kubelet context")
        ret = KubectlConfiguration().set_kubectl_context(Project_name,
                                                         VARIABLE_FILE,
                                                         SRC_PACKAGE_PATH)
        if not ret:
            logger.info('FAILED IN SETTING CONTEXT IN KUBECTL')

        Networks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
        logger.info(Networks)

        for item1 in Networks:
            for key in item1:
                if key == "Default_Network":
                    default_network = item1.get(consts.DEFAULT_NETWORK)
                    if default_network:
                        service_subnet = default_network.get(consts.SERVICE_SUBNET)
                        logger.info("Service subnet = %s", service_subnet)
                        pod_subnet = default_network.get(consts.POD_SUBNET)
                        logger.info("pod_subnet = %s", pod_subnet)
                        networking_plugin = default_network.get(consts.NETWORKING_PLUGIN)
                        logger.info("networking_plugin= %s", networking_plugin)
                    else:
                        logger.info("error: Default network configurations are "
                                    "not defined")


        ret = CleanupNetworkingPlugins().clean_up_flannel(hostname_map,
                                                          host_node_type_map,
                                                          networking_plugin,
                                                          config, Project_name)
        if not ret:
            logger.info('FAILED IN FLANNEL CLEANUP')

        logger.info('MACVLAN REMOVAL FOR CLUSTER')
        ret = macvlan_cleanup(config)
        if ret:
            logger.info('MACVLAN REMOVED SUCCESSFULLY')
        else:
            logger.info('MACVLAN NOT REMOVED')

        logger.info('DHCP REMOVAL FOR CLUSTER')
        dhcp_cni = get_dhcp_value(config)
        logger.info('dhcp value is %s', dhcp_cni)
        if dhcp_cni:
            ret = dhcp_cleanup(config)
            if ret:
                logger.info('DHCP REMOVED SUCCESSFULLY')
            else:
                logger.info('DHCP NOT REMOVED')
        else:
            logger.info('DHCP REMOVAL  EXIT , REASON--> DHCP  IS DISABLED ')

        ret = CleanupNetworkingPlugins().clean_up_weave(
            hostname_map, host_node_type_map, networking_plugin,
            config, Project_name)
        if not ret:
            logger.info('FAILED IN WEAVE CLEANUP')
        metrics_server = config.get(consts.KUBERNETES).get(consts.METRICS_SERVER)
        logger.info("metrics_server flag in kube8 deployment file is %s",
                    str(metrics_server))
        aconf.clean_up_k8_addons(hostname_map=hostname_map,
                                 host_node_type_map=host_node_type_map,
                                 metrics_server=metrics_server)
        ret = aconf.clean_up_k8(Git_branch, Project_name, multus_enabled)
        if not ret:
            logger.error('FAILED IN CLEANUP')
            exit(1)
        '''
        host_dict = get_cluster_hostname(Project_name)
        ret = aconf.clean_up_k8_docker(host_dict)
        if not ret:
            logger.error('FAILED IN DOCKER CLEANUP')
            exit(1)
        hosts_data_dict = get_sriov_nw_data(config)
        ret = aconf.clean_sriov_rc_local(hosts_data_dict)
        if not ret:
            logger.error('FAILED IN RC LOCAL CLEANUP')
            exit(1)
        '''
    logger.info('Exit')
    return ret

def __pushing_key(host_ip, user_name, password):
    """ Pushing key to  host"""
    logger.info("\n Argument List:" + "\n host_ip:" + host_ip +
                "\n user_name:" + user_name + "\n password:" + password)
    logger.info('PUSHING KEY TO HOSTS')
    command = "sshpass -p %s ssh-copy-id -o StrictHostKeyChecking=no %s@%s" \
    % (password, user_name, host_ip)
    res = subprocess.call(command, shell=True)
    if not res:
        logger.info('ERROR IN PUSHING KEY:Probably the key is already present'
                    ' in remote host')
    logger.info('SSH KEY BASED AUTH ENABLED')
    logger.info('Exit')


def __enable_key_ssh(hosts):
    logger.info("\n Argument List:" + "\n hosts:" + str(hosts))
    command = "sed -i '/#host_key_checking/c\host_key_checking = False' " + consts.ANSIBLE_CONF
    subprocess.call(command, shell=True)
    command_time = "sed -i '/#timeout = 10/c\\timeout = 50' " + consts.ANSIBLE_CONF
    subprocess.call(command_time, shell=True)
    for i in range(len(hosts)):
        user_name = hosts[i].get(consts.HOST).get(consts.USER)
        if user_name != 'root':
            logger.error('USER MUST BE ROOT')
            exit(1)
        password = hosts[i].get(consts.HOST).get(consts.PASSWORD)
        ip = hosts[i].get(consts.HOST).get(consts.IP)
        host_ip = ip
        check_dir = os.path.isdir(consts.SSH_PATH)
        if not check_dir:
            os.makedirs(consts.SSH_PATH)
            logger.info('Host ip is %s', host_ip)
            logger.info('GENERATING SSH KEY')
            subprocess.call('echo -e y|ssh-keygen -b 2048 -t rsa -f /root/.ssh/id_rsa -q -N ""',
                            shell=True)
        check_dir = os.path.isdir(consts.SSH_PATH)
        if check_dir:
            id_rsa_pub = Path("/root/.ssh/id_rsa.pub")
            id_rsa = Path("/root/.ssh/id_rsa")
            if not id_rsa.is_file():
                if id_rsa_pub.is_file():
                    os.remove("/root/.ssh/id_rsa.pub")
                logger.info('GENERATING SSH KEY')
                subprocess.call('echo -e y|ssh-keygen -b 2048 -t rsa -f /root/.ssh/id_rsa -q -N ""',
                                shell=True)
            if not id_rsa_pub.is_file():
                if id_rsa.is_file():
                    os.remove("/root/.ssh/id_rsa")
                logger.info('GENERATING SSH KEY')
                subprocess.call('echo -e y|ssh-keygen -b 2048 -t rsa -f /root/.ssh/id_rsa -q -N ""',
                                shell=True)
            ip = hosts[i].get(consts.HOST).get(consts.IP)
            host_ip = ip
            logger.info('PUSHING KEY TO HOSTS')
            command = "sshpass -p '%s' ssh-copy-id -o StrictHostKeyChecking=no %s@%s" \
            %(password, user_name, host_ip)
            logger.info(command)
            res = subprocess.call(command, shell=True)
            if res:
                logger.info('ERROR IN PUSHING KEY:Probably the key is ' + \
                            'already present in remote host')
            logger.info('SSH KEY BASED AUTH ENABLED')
    logger.info('Exit')
    return True

def __hostname_list(hosts):
    """Creating Host name list function"""
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

def __create_proxy_dic(config):
    """Creating proxy dictionary function"""
    logger.info("\n Argument List:" + "\n config:" + str(config))
    logger.info("Creating Proxy dictionary")
    proxy_dic = {}
    http_proxy = config.get(consts.KUBERNETES).get(
        consts.PROXIES).get(consts.HTTP_PROXY)
    https_proxy = config.get(consts.KUBERNETES).get(
        consts.PROXIES).get(consts.HTTPS_PROXY)
    ftp_proxy = config.get(consts.KUBERNETES).get(
        consts.PROXIES).get(consts.FTP_PROXY)
    no_proxy = config.get(consts.KUBERNETES).get(
        consts.PROXIES).get(consts.NO_PROXY)

    if http_proxy:
        proxy_dic['http_proxy'] = "\"" + http_proxy + "\""
    else:
        proxy_dic['http_proxy'] = ''
    if https_proxy:
        proxy_dic['https_proxy'] = "\"" + https_proxy + "\""
    else:
        proxy_dic['https_proxy'] = ''
    if ftp_proxy:
        proxy_dic['ftp_proxy'] = "\"" + ftp_proxy + "\""
    else:
        proxy_dic['ftp_proxy'] = ''
    if no_proxy:
        proxy_dic['no_proxy'] = "\"" + no_proxy + "\""
    else:
        proxy_dic['no_proxy'] = ''
    logger.info("Done with proxies")
    logger.info('Exit')
    return proxy_dic

def get_sriov_nw_data(config):
    logger.info("\n Argument List:" + "\n config:" + str(config))
    networks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
    cni_configuration = ""
    for item1 in networks:
        for key in item1:
            logger.info('Key is %s', key)
            if key == "Multus_network":
                multus_network = item1.get("Multus_network")
                for item2 in multus_network:
                    for key in item2:
                        if key == "CNI_Configuration":
                            cni_configuration = item2.get("CNI_Configuration")
                        else:
                            logger.info('CNI_Configuration tag not found in config data')
            else:
                logger.info('Multus_network tag not found in config data')
                return cni_configuration

    logger.info('Exit')
    return cni_configuration

def __get_credentials(config):
    """get credentials function"""
    logger.info("\n Argument List:" + "\n config:" + str(config))
    credential_dic = {}
    hosts = config.get(consts.KUBERNETES).get(consts.HOSTS)
    for i in range(len(hosts)):
        user = hosts[i].get(consts.HOST).get(consts.USER)
        password = hosts[i].get(consts.HOST).get(consts.PASSWORD)
        credential_dic['user'] = user
        credential_dic['password'] = password

    logger.info('Exit')
    return credential_dic

def get_hostname_map(hosts):
    """Get hostname map function"""
    logger.info("\n Argument List:" + "\n hosts:" + str(hosts))
    if hosts:
        hostname_map = {}
        for i in range(len(hosts)):
            hostname = hosts[i].get(consts.HOST).get('hostname')
            host_ip = ""
            ip = hosts[i].get(consts.HOST).get(consts.IP)
            if ip:
                host_ip = ip
            hostname_map[hostname] = host_ip

    logger.info('Exit')
    return hostname_map

def __enabling_basic_authentication(basic_authentication, Project_name):
    """Basic Authentication function"""
    logger.info("\n Argument List:" + "\n basic_authentication:" +
                str(basic_authentication) + "\n Project_name:" + Project_name)

    for i in range(len(basic_authentication)):
        user_name = basic_authentication[i].get(
            consts.USER).get(consts.USER_NAME)
        user_password = basic_authentication[i].get(
            consts.USER).get(consts.USER_PASSWORD)
        user_id = basic_authentication[i].get(
            consts.USER).get(consts.USER_ID)
        ret = aconf.modify_user_list(user_name, user_password, user_id)
        if not ret:
            logger.error('FAILED IN DEPLOY')
            exit(1)

    master_host_name = aconf.get_host_master_name(Project_name)
    logger.info('UPDATE KUBE API MANIFEST FILE')
    ret = aconf.update_kube_api_manifest_file(master_host_name)
    if not ret:
        logger.error('FAILED TO UPDATE KUBE API FILE')
        exit(1)
    time.sleep(5)

    logger.info('Exit')
    return ret

def _modifying_etcd_node(Project_name, hostname_map, host_node_type_map):
    """etcd modification changes"""
    logger.info("\n Argument List:" + "\n Project_name:" + Project_name +
                "\n hostname_map:" + str(hostname_map) +
                "\n host_node_type_map:" + str(host_node_type_map))

    for host_name, node_type in host_node_type_map.iteritems():
        if node_type == "master":
            master_host_name = host_name
    for host_name, ip in hostname_map.iteritems():
        if host_name == master_host_name:
            master_ip = ip
    logger.info('master ip --->'+master_ip+'  master host name --->'+ master_host_name)
    VARIABLE_FILE = consts.VARIABLE_FILE
    SRC_PACKAGE_PATH = consts.INVENTORY_SOURCE_FOLDER
    logger.info('EXECUTING ETCD Changes')
    playbook_path_etcd_changes = consts.ETCD_CHANGES
    logger.info(playbook_path_etcd_changes)
    ret_hosts = ansible_playbook_launcher.launch_ansible_playbook_etcd_changes(
        playbook_path_etcd_changes, master_host_name, master_ip,
        SRC_PACKAGE_PATH, VARIABLE_FILE)
    if not ret_hosts:
        logger.error('FAILED SET HOSTS PLAY')
        exit(1)
    logger.info('Exit')
    return ret_hosts

def __create_host_nodetype_map(hosts):
    """Get Node types function"""
    logger.info("\n Argument List:" + "\n hosts:" + str(hosts))
    hostnode_map = {}
    if hosts:
        for i in range(len(hosts)):
            node_type = hosts[i].get(consts.HOST).get(consts.NODE_TYPE)
            hostname = hosts[i].get(consts.HOST).get('hostname')
            hostnode_map[hostname] = node_type
    logger.info('Exit')
    return hostnode_map

def __create_host_port_map(hosts):
    logger.info("\n Argument List:" + "\n hosts:" + str(hosts))
    hostport_map = {}
    if hosts:
        for i in range(len(hosts)):
            registry_port = hosts[i].get(consts.HOST).get('registry_port')
            hostname = hosts[i].get(consts.HOST).get('hostname')
            hostport_map[hostname] = registry_port
    logger.info('Exit')
    return hostport_map

def __add_ansible_hosts(hosts):
    """
    This will add the ansible hosts into the ansible hosts file placed at /etc/ansible/hosts
    """
    logger.info("\n Argument List:" + "\n hosts:" + str(hosts))
    if hosts:
        host_str = ""
        ansible_host_str = ""
        host_ip = ""
        ansible_host_file = open(consts.ANSIBLE_HOSTS_FILE, "r+")
        host_file = open(consts.HOSTS_FILE, "r+")
        ansible_file_content = ""
        file_content = ""
        for line in ansible_host_file:
            ansible_file_content = ansible_file_content + line
        for line in host_file:
            file_content = file_content + line
        for i in range(len(hosts)):
            host_ip = hosts[i].get(consts.HOST).get(consts.IP) + " "
            host_name = hosts[i].get(consts.HOST).get(consts.HOSTNAME) + " "
            logger.info('host_ip is %s', host_ip)
            logger.info('Hostname is %s', host_name)
            if (host_ip in ansible_file_content and
                    host_name in ansible_file_content):
                pass
            else:
                ansible_host_str = "\n" + host_name + "\n" + host_ip + "\n" + ansible_host_str
            if host_ip in file_content and host_name in file_content:
                pass
            else:
                host_str = "\n" + host_ip + " " + host_name + "\n" + host_str
        logger.info(host_str)
        logger.info("Host entries in %s", consts.HOSTS_FILE)
        host_file.write(host_str)
        logger.info("Host entries in %s", consts.ANSIBLE_HOSTS_FILE)
        ansible_host_file.write(ansible_host_str)
        host_file.close()
    logger.info('Exit')

def get_master_ip(Project_name):
    logger.info("\n Argument List:" + "\n Project_name:" + Project_name)
    config = file_utils.read_yaml(consts.VARIABLE_FILE)
    project_path = config.get(consts.PROJECT_PATH)
    inventory_file_path = project_path+Project_name+"/inventory.cfg"
    master_hostname = None
    logger.info('Inventory file path get_master_ip function is %s', inventory_file_path)

    with open(inventory_file_path) as f:
        for line in f:
            if re.match("\[kube\-master\]", line):
                master_hostname1 = f.next()
                master_hostname = master_hostname1.strip(' \t\n\r')
                logger.info('master_hostname is %s', master_hostname)

    with open(inventory_file_path) as f:
        for line in f:
            if "ansible_ssh_host=" in line:
                host_ip1 = line.split("ansible_ssh_host=", 1)[1]
                host_ip = host_ip1.strip(' \t\n\r')
                hostnamestringlist = line.split(" ")
                host_name = hostnamestringlist[0]
                host_name = host_name.strip(' \t\n\r')
                if host_ip:
                    logger.info('Hostname is %s', host_name)
                    logger.info('master_hostname is %s', master_hostname)
                    if host_name == master_hostname:
                        master_ip = host_ip
    logger.info('Exit')
    return master_ip

def __noOfNetworkInFlannel_list(config):
    """Creating flannelNetwork list function"""
    logger.info("\n Argument List:" + "\n config:" + str(config))
    logger.info("Creating noOfNetworksInFlannel list")
    flannelNetworks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
    logger.info('flannelNetworks is %s', str(flannelNetworks))
    flannelNetworkList = []
    for Network in flannelNetworks:
        if Network != None:
            flannelNetworkList = Network.get(consts.FLANNEL_NETWORK)
    logger.info('Exit')
    return flannelNetworks

def __noOfNetworkInWeave_list(config):
    """Creating weaveNetwork list function"""
    logger.info("\n Argument List:" + "\n config:" + str(config))
    logger.info("Creating noOfNetworksInWeave list")
    weaveNetworkList = []
    hosts_data_dict = get_flannel_nw_data(config)
    for item1 in hosts_data_dict:
        for key in item1:
            if key == "Multus_network":
                multus_network = item1.get("Multus_network")
                for item2 in multus_network:
                    for key in item2:
                        if key == "CNI_Configuration":
                            weaveNetworks = item2.get("CNI_Configuration")
                            for item3 in weaveNetworks:
                                for key in item3:
                                    if consts.WEAVE_NETWORK == key:
                                        weaveNetworkList = item3.get(consts.WEAVE_NETWORK)

    logger.info('Exit')
    return weaveNetworks

def remove_macvlan_networks(config, macvlan_master_hostname):
    """
    This method is used for remove macvlan network after multus
    :param config :input configuration file
    :return ret :t/f
    """
    logger.info("\n Argument List:" + "\n config:" + str(config) +
                "\n macvlan_master_hostname:" + macvlan_master_hostname)
    ret = False
    if config:
        macvlan_network_removal_playbook = consts.K8_MACVLAN_NETWORK_REMOVAL_PATH
        logger.info('Removal_mac_vlan networks')
        PROXY_DATA_FILE = consts.PROXY_DATA_FILE
        noOfNetwroksInMacvlan = config.get(consts.KUBERNETES).get(
            consts.NETWORK_CREATION_IN_MACVLAN)
        for item1 in noOfNetwroksInMacvlan:
            for key in item1:
                if key == "Multus_network":
                    multus_network = item1.get("Multus_network")
                    for item2 in multus_network:
                        for key in item2:
                            if key == "CNI_Configuration":
                                cni_configuration = item2.get("CNI_Configuration")
                                for item3 in cni_configuration:
                                    for key in item3:
                                        if key == "Macvlan":
                                            macvlan_network1 = item3.get("Macvlan")
                                            for macvlan_networks in macvlan_network1:
                                                inetfaceDict = macvlan_networks.get("macvlan_networks")
                                                macvlan_network_name = inetfaceDict.get("network_name")
                                                logger.info('macvlan_master_hostname is %s', macvlan_master_hostname)
                                                logger.info('macvlan_network_name is %s', macvlan_network_name)

                                                ret = ansible_playbook_launcher.launch_ansible_playbook_network_removal(
                                                    macvlan_network_removal_playbook,
                                                    macvlan_master_hostname,
                                                    macvlan_network_name,
                                                    PROXY_DATA_FILE)
                                                if not ret:
                                                    logger.info('FAILED IN MACVLAN network removal_master')

    logger.info('Exit')
    return ret

def configure_macvlan_interface(config):    #function for mac-vlan network creation
    """
    This method is used for create macvlan interface list after multus
    :param config :input configuration file
    :return ret :t/f
    """
    logger.info("\n Argument List:" + "\n config:" + str(config))
    ret = False
    if config:
        vlan_playbook = consts.K8_VLAN_INTERFACE_PATH
        logger.info('configure_mac_vlan interfaces')
        noOfNetwroksInMacvlan = config.get(consts.KUBERNETES).get(consts.NETWORK_CREATION_IN_MACVLAN)
        for item1 in noOfNetwroksInMacvlan:
            for key in item1:
                if key == "Multus_network":
                    multus_network = item1.get("Multus_network")
                    for item2 in multus_network:
                        for key in item2:
                            if key == "CNI_Configuration":
                                cni_configuration = item2.get("CNI_Configuration")
                                for item3 in cni_configuration:
                                    for key in item3:
                                        if key == "Macvlan":
                                            macvlan_network1 = item3.get("Macvlan")
                                            for macvlan_networks in macvlan_network1:
                                                inetfaceDict = macvlan_networks.get("macvlan_networks")
                                                macvlan_parent_interface = inetfaceDict.get("parent_interface")
                                                macvlan_vlanid = inetfaceDict.get("vlanid")
                                                macvlan_ip = inetfaceDict.get("ip")
                                                macvlan_node_hostname = inetfaceDict.get("hostname")
                                                logger.info('macvlan_node_hostname is %s', macvlan_node_hostname)
                                                logger.info('macvlan_parent_interface is %s', macvlan_parent_interface)
                                                logger.info('macvlan_vlanid is %s', macvlan_vlanid)
                                                logger.info('macvlan_ip is %s', macvlan_ip)

                                                ret = ansible_playbook_launcher.launch_ansible_playbook_node_vlantag_interface(
                                                    vlan_playbook, macvlan_node_hostname,
                                                    macvlan_parent_interface,
                                                    macvlan_vlanid, macvlan_ip)
                                                if not ret:
                                                    logger.error('FAILED IN MACVLAN interface creation')

    logger.info('Exit')
    return ret


def removal_macvlan_interface(config):
    """
    This method is used for create macvlan network after multus
    :param config :input configuration file
    :return ret :t/f
    """
    logger.info("\n Argument List:" + "\n config:" + str(config))
    ret = False
    if config:
        vlan_removal_playbook = consts.K8_VLAN_INTERFACE_REMOVAL_PATH
        logger.info('Removal_mac_vlan interfaces')
        noOfNetwroksInMacvlan = config.get(consts.KUBERNETES).get(consts.NETWORK_CREATION_IN_MACVLAN)
        for item1 in noOfNetwroksInMacvlan:
            for key in item1:
                if key == "Multus_network":
                    multus_network = item1.get("Multus_network")
                    for item2 in multus_network:
                        for key in item2:
                            if key == "CNI_Configuration":
                                cni_configuration = item2.get("CNI_Configuration")
                                for item3 in cni_configuration:
                                    for key in item3:
                                        if key == "Macvlan":
                                            macvlan_network1 = item3.get("Macvlan")
                                            for macvlan_networks in macvlan_network1:
                                                inetfaceDict = macvlan_networks.get("macvlan_networks")
                                                macvlan_parent_interface = inetfaceDict.get("parent_interface")
                                                macvlan_vlanid = inetfaceDict.get("vlanid")
                                                macvlan_node_hostname = inetfaceDict.get("hostname")
                                                logger.info('macvlan_node_hostname is %s', macvlan_node_hostname)
                                                logger.info('macvlan_parent_interface is %s', macvlan_parent_interface)
                                                logger.info('macvlan_vlanid is %s', macvlan_vlanid)

                                                ret = ansible_playbook_launcher.launch_ansible_playbook_node_vlantag_interface_removal(
                                                    vlan_removal_playbook, macvlan_node_hostname,
                                                    macvlan_parent_interface, macvlan_vlanid)
                                                if not ret:
                                                    logger.error('FAILED IN MACVLAN interface removal')

    logger.info('Exit')
    return ret

def macvlan_cleanup(config):
    logger.info("\n Argument List:" + "\n config:" + str(config))
    logger.info("MACVLAN PLUGIN REMOVAL")
    ret = False
    macvlan_cni = get_macvlan_value(config)
    logger.info('macvlan value n macvlan_cleanup function:%s', macvlan_cni)
    if macvlan_cni:
        logger.info('REMOVING MACVLAN')
        ret = removal_macvlan_interface(config)
        Project_name = config.get(consts.KUBERNETES).get(consts.PROJECT_NAME)
        master_node_macvlan = aconf.get_host_master_name(Project_name)
        ret = remove_macvlan_networks(config, master_node_macvlan)
    else:
        logger.info('MAC-VLAN CONFIGURATION  EXIT , REASON--> MACVLAN  IS DISABLED ')
        ret = False
    logger.info('Exit')
    return ret


def __macvlan_installation(config):
    logger.info("\n Argument List:" + "\n config:" + str(config))
    logger.info('CONFIGURING MAC-VLAN')
    ret = MultusNetworkingPluginsAddition().configure_macvlan_interface(config)
    Project_name = config.get(consts.KUBERNETES).get(consts.PROJECT_NAME)
    master_node_macvlan = aconf.get_host_master_name(Project_name)
    ret = MultusNetworkingPluginsAddition().configure_macvlan_networks(config, master_node_macvlan)
    logger.info('Exit')
    return ret


def get_macvlan_value(config):
    """
    This function is used to get multus cni value
    """
    logger.info("\n Argument List:" + "\n config:" + str(config))
    ret = False
    noOfNetworks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
    for item1 in noOfNetworks:
        for key in item1:
            if key == "Multus_network":
                multus_network = item1.get("Multus_network")
                for item2 in multus_network:
                    for key in item2:
                        if key == "CNI":
                            multus_cni = item2.get("CNI")
                            if multus_cni:
                                for cni in multus_cni:
                                    if cni == "macvlan":
                                        ret = True

    logger.info('Exit')
    return ret


def dhcp_cleanup(config):
    logger.info("\n Argument List:" + "\n config:" + str(config))
    logger.info('REMOVING DHCP')
    noOfhosts_fornetwork = config.get(consts.KUBERNETES).get(consts.HOSTS)
    for dhcp_host_fornetwork in noOfhosts_fornetwork:
        if dhcp_host_fornetwork != None:
            inetfaceDict_fornetwork = dhcp_host_fornetwork.get("host")
            hostname_fornetwork = inetfaceDict_fornetwork.get("hostname")
            node_type_fornetwork = inetfaceDict_fornetwork.get("node_type")
            if node_type_fornetwork == "minion":
                dhcp_daemon_removal_playbook = consts.K8_DHCP_REMOVAL_PATH
                logger.info('DHCP DAEMON REMOVING')
                ret = ansible_playbook_launcher.launch_ansible_playbook_dhcp_daemon_removal(
                    dhcp_daemon_removal_playbook, hostname_fornetwork)
                if not ret:
                    logger.info('FAILED IN DHCP REMOVAL---------------')
    logger.info('Exit')
    return ret

def get_flannel_nw_data(config):
    """
    This function is used for get the flannel network info
    """
    logger.info("\n Argument List:" + "\n config:" + str(config))
    hosts_data_dict = config.get(consts.KUBERNETES).get(consts.NETWORKS)
    logger.info('Exit')
    return hosts_data_dict

def get_multus_cni_value(config):
    """
    This function is used to get multus cni value
    """
    logger.info("\n Argument List:" + "\n config:" + str(config))
    ret = False
    sriov_cni = False
    flannel_cni = False
    weave_cni = False
    macvlan_cni = False
    noOfNetworks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
    for item1 in noOfNetworks:
        for key in item1:
            if key == "Multus_network":
                multus_network = item1.get("Multus_network")
                for item2 in multus_network:
                    for key in item2:
                        if key == "CNI":
                            multus_cni = item2.get("CNI")
                            if multus_cni:
                                for cni in multus_cni:
                                    if cni == "sriov":
                                        sriov_cni = True
                                    elif cni == consts.FLANNEL:
                                        flannel_cni = True
                                    elif cni == consts.WEAVE:
                                        weave_cni = True
                                    elif cni == "macvlan":
                                        macvlan_cni = True

        ret = sriov_cni or flannel_cni or weave_cni or macvlan_cni

    logger.info('Exit')
    return ret

def __create_default_network_multus(config, hostname_map, host_node_type_map,
                                    service_subnet, pod_subnet, networking_plugin):
    """
    This function is used to create default network
    """
    logger.info("\n Argument List:" + "\n config:" + str(config) +
                "\n hostname_map:" + str(hostname_map) +
                "\n host_node_type_map:" + str(host_node_type_map) +
                "\n service_subnet:" + service_subnet + "\n pod_subnet:" +
                pod_subnet + "\n networking_plugin:" + networking_plugin)
    ret = False
    noOfNetworks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
    if networking_plugin == "weave" or networking_plugin == "flannel":
        for item1 in noOfNetworks:
            for key in item1:
                if key == "Default_Network":
                    default_network = item1.get(consts.DEFAULT_NETWORK)
                    if default_network:
                        ret = aconf.create_default_network(
                            hostname_map, host_node_type_map, service_subnet,
                            pod_subnet, networking_plugin, default_network)
    else:
        logger.info('Cannot create default network as default networking ' +
                    'plugin is other than flannel/weave')

    logger.info('Exit')
    return ret

def launch_flannel_interface(config, hostname_map, host_node_type_map,
                             networking_plugin, Project_name):
    """
    This function is used to create flannel interface
    """
    logger.info("\n Argument List:" + "\n config:" + str(config) +
                "\n hostname_map:" + str(hostname_map)  +
                "\n host_node_type_map:" + str(host_node_type_map) +
                "\n networking_plugin:" + networking_plugin  +
                "\n Project_name:" + Project_name)
    ret = False
    if networking_plugin != "flannel":
        hosts_data_dict = get_flannel_nw_data(config)
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
                                            ret = aconf.create_flannel_interface(
                                                hostname_map, host_node_type_map,
                                                networking_plugin, Project_name, hosts_data_dict)
    else:
        logger.error('FLANNEL IS ALREADY CONFIGURED AS DEFAULT NETWORKING PLUGIN, ' +
                     'PLEASE PROVIDE MULTUS PLUGIN OTHER THAN FLANNEL')
        exit(1)

    logger.info('Exit')
    return ret

def __launch_weave_interface(config, hostname_map, host_node_type_map, service_subnet, pod_subnet, networking_plugin):
    """
    This function is used to create weave interface
    """
    logger.info("\n Argument List:" + "\n config:" + str(config) +
                "\n hostname_map:" + hostname_map + "\n host_node_type_map:" +
                str(host_node_type_map) + "\n service_subnet:" +
                service_subnet + "\n pod_subnet:" + pod_subnet +
                "\n networking_plugin:" + networking_plugin)
    ret = False
    if networking_plugin != "weave":
        weaveNetworkList_map = __noOfNetworkInWeave_list(config)
        logger.info('weaveNetworkList_map is %s', str(weaveNetworkList_map))
        for item in weaveNetworkList_map:
            for key in item:
                if consts.WEAVE_NETWORK == key:
                    weave_network = item.get(consts.WEAVE_NETWORK)
                    for item1 in weave_network:
                        ret = aconf.create_weave_interface(
                            hostname_map, host_node_type_map, service_subnet,
                            pod_subnet, networking_plugin, item1)
    else:
        logger.error('WEAVE IS ALREADY CONFIGURED AS DEFAULT NETWORKING ' + \
                     'PLUGIN, PLEASE PROVIDE MULTUS PLUGIN OTHER THAN WEAVE')
        exit(1)

    logger.info('Exit')
    return ret

def get_macvlan_value(config):
    """
    This function is used to get multus cni value
    """
    logger.info("\n Argument List:" + "\n config:" + str(config))
    ret = False
    noOfNetworks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
    for item1 in noOfNetworks:
        for key in item1:
            if key == "Multus_network":
                multus_network = item1.get("Multus_network")
                for item2 in multus_network:
                    for key in item2:
                        if key == "CNI":
                            multus_cni = item2.get("CNI")
                            if multus_cni:
                                for cni in multus_cni:
                                    if cni == "macvlan":
                                        ret = True

    logger.info('Exit')
    return ret


def get_dhcp_value(config):
    """
    This function is used to get multus cni value
    """
    logger.info("\n Argument List:" + "\n config:" + str(config))
    ret = False
    noOfNetworks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
    for item1 in noOfNetworks:
        for key in item1:
            if key == "Multus_network":
                multus_network = item1.get("Multus_network")
                for item2 in multus_network:
                    for key in item2:
                        if key == "CNI":
                            multus_cni = item2.get("CNI")
                            if multus_cni:
                                for cni in multus_cni:
                                    if cni == "dhcp":
                                        ret = True

    logger.info('Exit')
    return ret

def get_flannel_value(config):
    """
    This function is used to get multus cni value
    """
    logger.info("\n Argument List:" + "\n config:" + str(config))
    ret = False
    noOfNetworks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
    for item1 in noOfNetworks:
        for key in item1:
            if key == "Multus_network":
                multus_network = item1.get("Multus_network")
                for item2 in multus_network:
                    for key in item2:
                        if key == "CNI":
                            multus_cni = item2.get("CNI")
                            if multus_cni:
                                for cni in multus_cni:
                                    if cni == "flannel":
                                        ret = True

    logger.info('Exit')
    return ret

def get_weave_nw_data(config):
    """
    This function is used for get the weave network info
    """
    logger.info("\n Argument List:" + "\n config:" + str(config))
    hosts_data_dict = config.get(consts.KUBERNETES).get(consts.NETWORKS)
    logger.info('Exit')
    return hosts_data_dict

def create_backup_deploy_conf(config, deploy_file):
    """
    This function is used to create backup file for deployment configuration
    """
    logger.info("\n Argument List:" + "\n config:" + str(config) + "\n deploy_file" + deploy_file)
    ret = True

    Project_name = config.get(consts.KUBERNETES).get(consts.PROJECT_NAME)
    CURRENT_DIR = consts.CWD1
    VARIABLE_FILE = consts.VARIABLE_FILE
    config = file_utils.read_yaml(VARIABLE_FILE)
    project_path = config.get(consts.PROJECT_PATH)
    src = CURRENT_DIR + deploy_file
    logger.info(src)
    dst = project_path + Project_name + "/" + consts.BKUP_DEPLOYMENT_FILE
    logger.info(dst)
    copyfile(src, dst)

    logger.info('Exit')
    return ret

def get_multus_cni_value_for_dynamic_node(config):
    """
    This function is used to get multus cni value for dynamic node
    """
    logger.info("\n Argument List:" + "\n config:" + str(config))
    ret = check_multus_cni_deploy_config(config)
    if ret:
        logger.info("Setting multus_cni to true, as flannel/weave was "
                    "enabled as additional plugin at cluster creation")

    logger.info('Exit')
    return ret


def check_multus_cni_deploy_config(config):
    """
    This function is used to get multus cni value configured at cluster creation
    """
    logger.info("\n Argument List:" + "\n config:" + str(config))
    ret = False
    flannel_cni = False
    weave_cni = False
    logger.info("Function check_multus_cni_deploy_config")
    Project_name = config.get(consts.KUBERNETES).get(consts.PROJECT_NAME)
    CURRENT_DIR = consts.CWD
    VARIABLE_FILE = consts.VARIABLE_FILE
    config = file_utils.read_yaml(VARIABLE_FILE)
    project_path = config.get(consts.PROJECT_PATH)
    src = project_path + Project_name + "/" + consts.BKUP_DEPLOYMENT_FILE
    dst = CURRENT_DIR + consts.BKUP_DEPLOYMENT_FILE
    logger.info('Deployment file path, src is ' + src + ' and dst is ' + dst)
    copyfile(src, dst)
    #config1 = file_utils.read_yaml(consts.BKUP_DEPLOYMENT_FILE)
    config1 = file_utils.read_yaml(dst)
    noOfNetworks = config1.get(consts.KUBERNETES).get(consts.NETWORKS)
    if config1:
        for item1 in noOfNetworks:
            for key in item1:
                if key == "Multus_network":
                    multus_network = item1.get("Multus_network")
                    for item2 in multus_network:
                        for key in item2:
                            if key == "CNI":
                                multus_cni = item2.get("CNI")
                                if multus_cni:
                                    for cni in multus_cni:
                                        if cni == "flannel":
                                            flannel_cni = True
                                        elif cni == "weave":
                                            weave_cni = True

        os.remove(dst)

    ret = flannel_cni or weave_cni

    logger.info('Exit')
    return ret

def get_weave_value(config):
    """
    This function is used to get multus cni value
    """
    logger.info("\n Argument List:" + "\n config:" + str(config))
    ret = False
    noOfNetworks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
    for item1 in noOfNetworks:
        for key in item1:
            if key == "Multus_network":
                multus_network = item1.get("Multus_network")
                for item2 in multus_network:
                    for key in item2:
                        if key == "CNI":
                            multus_cni = item2.get("CNI")
                            if multus_cni:
                                for cni in multus_cni:
                                    if cni == "weave":
                                        ret = True

    logger.info('Exit')
    return ret

# Get project_path
def get_project_path():
    """
    This function is used for get the project path
    """
    VARIABLE_FILE = consts.VARIABLE_FILE
    config = file_utils.read_yaml(VARIABLE_FILE)
    project_path = config.get(consts.PROJECT_PATH)
    logger.info('Exit')
    return project_path

# Validate if project exist
def validate_project(project_name):
    """
    This function is used for validate project
    """
    logger.info("\n Argument List:" + "\n project_name:" + project_name)
    project_path = get_project_path()
    logger.info(project_path)
    if os.path.isdir(project_path + project_name):
        logger.info('Exit')
        return project_path
    else:
        logger.info('Exit')
        return None


def get_sriov_value(config):
    """
    This function is used to get sriov value
    """
    logger.info("\n Argument List:" + "\n config:" + str(config))
    ret = False
    noOfNetworks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
    for item1 in noOfNetworks:
        for key in item1:
            if key == "Multus_network":
                multus_network = item1.get("Multus_network")
                for item2 in multus_network:
                    for key in item2:
                        if key == "CNI":
                            multus_cni = item2.get("CNI")
                            if multus_cni != None:
                                for cni in multus_cni:
                                    if cni == "sriov":
                                        ret = True
    logger.info('Exit')
    return ret


class CleanupNetworkingPlugins(object):
    def __init__(self):
        pass

    def clean_up_flannel(self, hostname_map, host_node_type_map,
                         networking_plugin, config, Project_name):
        """
        This function is used to clean the flannel additional plugin
        """
        logger.info("\n Argument List:" + "\n hostname_map:" +
                    str(hostname_map) + "\n host_node_type_map:" +
                    str(host_node_type_map) + "\n networking_plugin:" +
                    networking_plugin + "\n config:" + str(config) +
                    "\n Project_name:" + Project_name)
        ret = False
        flannel_cni = False
        if config:
            if networking_plugin != "flannel":
                flannel_cni = get_flannel_value(config)
                hosts_data_dict = get_flannel_nw_data(config)
                if flannel_cni:
                    ret = CleanUpMultusPlugins().delete_flannel_interfaces(
                        hostname_map, host_node_type_map,
                        hosts_data_dict, Project_name)
                    if not ret:
                        logger.info('FAILED IN FLANNEL INTERFACE DELETION')
            else:
                ret = True
        else:
            logger.info('FLANNEL IS DEFAULT PLUGIN')
            ret = True

        logger.info('Exit')
        return ret

#########clean up weave############
    def clean_up_weave(self, hostname_map, host_node_type_map,
                       networking_plugin, config, Project_name):
        """
        This function is used to clean the weave additional plugin
        """
        logger.info("\n Argument List:" + "\n hostname_map:" +
                    str(hostname_map) + "\n host_node_type_map:" +
                    str(host_node_type_map) + "\n networking_plugin:" +
                    networking_plugin + "\n config:" + str(config) +
                    "\n Project_name:" + Project_name)
        ret = False
        weave_cni = False
        if config:
            if networking_plugin != "weave":
                logger.info('DEFAULT NETWOKRING PLUGUN IS NOT WEAVE.. CHECK MULTUS CNI PLUGINS')
                weave_cni = get_weave_value(config)
                hosts_data_dict = get_weave_nw_data(config)
                if weave_cni:
                    ret = CleanUpMultusPlugins().delete_weave_interface(
                        hostname_map, host_node_type_map,
                        hosts_data_dict, Project_name)
                    if not ret:
                        logger.info('FAILED IN WEAVE INTERFACE DELETION')
                else:
                    ret = True
            else:
                logger.info('WEAVE IS DEFAULT PLUGIN')
                hosts_data_dict = get_weave_nw_data(config)
                ret = CleanUpMultusPlugins().delete_default_weave_interface(
                    hostname_map, host_node_type_map,
                    hosts_data_dict, Project_name)
                if not ret:
                    logger.info('FAILED IN WEAVE INTERFACE DELETION')

        logger.info('Exit')
        return ret

class MultusNetworkingPluginsAddition(object):
    def __init__(self):
        pass


    def configure_macvlan_networks(self, config, macvlan_master_hostname):
        """
        This method is used for create macvlan network after multus
        :param config :input configuration file
        :return ret :t/f
        """
        logger.info("\n Argument List:" + "\n config:" + str(config) +
                    "\n macvlan_master_hostname:" + macvlan_master_hostname)
        ret = False
        if config:
            macvlan_master_network_playbook = consts.K8_MACVLAN_MASTER_NETWORK_PATH
            macvlan_network_playbook = consts.K8_MACVLAN_NETWORK_PATH
            macvlan_master_network_dhcp_playbook = consts.K8_MACVLAN_MASTER_NETWORK_DHCP_PATH
            macvlan_network_dhcp_playbook = consts.K8_MACVLAN_NETWORK_DHCP_PATH
            PROXY_DATA_FILE = consts.PROXY_DATA_FILE
            logger.info('configure_mac_vlan networks')
            noOfNetwroksInMacvlan = config.get(consts.KUBERNETES).get(
                consts.NETWORK_CREATION_IN_MACVLAN)
            for item1 in noOfNetwroksInMacvlan:
                for key in item1:
                    if key == "Multus_network":
                        multus_network = item1.get("Multus_network")
                        for item2 in multus_network:
                            for key in item2:
                                if key == "CNI_Configuration":
                                    cni_configuration = item2.get("CNI_Configuration")
                                    for item3 in cni_configuration:
                                        for key in item3:
                                            if key == "Macvlan":
                                                macvlan_network1 = item3.get("Macvlan")
                                                for macvlan_networks in macvlan_network1:
                                                    inetfaceDict = macvlan_networks.get("macvlan_networks")
                                                    macvlan_gateway = inetfaceDict.get("gateway")
                                                    macvlan_master = inetfaceDict.get("master")
                                                    macvlan_masterplugin = inetfaceDict.get(consts.MASTER_PLUGIN)
                                                    macvlan_network_name = inetfaceDict.get("network_name")
                                                    macvlan_rangeStart = inetfaceDict.get("rangeStart")
                                                    macvlan_rangeEnd = inetfaceDict.get("rangeEnd")
                                                    macvlan_routes_dst = inetfaceDict.get("routes_dst")
                                                    macvlan_subnet = inetfaceDict.get("subnet")
                                                    macvlan_type = inetfaceDict.get("type")
                                                    macvlan_node_hostname = inetfaceDict.get("hostname")
                                                    logger.info('macvlan_node_hostname is %s', macvlan_node_hostname)
                                                    logger.info('macvlan_gateway is %s', macvlan_gateway)
                                                    logger.info('macvlan_master_hostname is %s', macvlan_master_hostname)
                                                    logger.info('macvlan_master is %s', macvlan_master)
                                                    logger.info('macvlan_masterplugin is %s', macvlan_masterplugin)
                                                    logger.info('macvlan_network_name is %s', macvlan_network_name)
                                                    logger.info('macvlan_rangeStart is %s', macvlan_rangeStart)
                                                    logger.info('macvlan_rangeEnd is %s', macvlan_rangeEnd)
                                                    logger.info('macvlan_routes_dst is %s', macvlan_routes_dst)
                                                    logger.info('macvlan_subnet is %s', macvlan_subnet)
                                                    logger.info('macvlan_type is %s', macvlan_type)

                                                    if macvlan_masterplugin == "true":
                                                        if macvlan_type == "host-local":
                                                            logger.info('Master plugin is true && type is host-local')
                                                            ret = ansible_playbook_launcher.launch_ansible_playbook_network_creation(macvlan_master_network_playbook, macvlan_master_hostname, macvlan_network_name, macvlan_master, macvlan_subnet, macvlan_rangeStart, macvlan_rangeEnd, macvlan_routes_dst, macvlan_gateway, PROXY_DATA_FILE)
                                                            if not ret:
                                                                logger.error('FAILED IN MACVLAN network creation_master1')
                                                        if macvlan_type == "dhcp":
                                                            logger.info('Master plugin is true && type is dhcp')
                                                            ret = ansible_playbook_launcher.launch_ansible_playbook_network_dhcp_creation(macvlan_master_network_dhcp_playbook, macvlan_master_hostname, macvlan_network_name, macvlan_master, PROXY_DATA_FILE)
                                                            if not ret:
                                                                logger.error('FAILED IN MACVLAN network creation_master2')

                                                    if macvlan_masterplugin == "false":
                                                        if macvlan_type == "host-local":
                                                            logger.info('Master plugin is false && type is host-local')
                                                            ret = ansible_playbook_launcher.launch_ansible_playbook_network_creation(macvlan_network_playbook, macvlan_master_hostname, macvlan_network_name, macvlan_master, macvlan_subnet, macvlan_rangeStart, macvlan_rangeEnd, macvlan_routes_dst, macvlan_gateway, PROXY_DATA_FILE)
                                                            if not ret:
                                                                logger.error('FAILED IN MACVLAN network creation1')
                                                        if macvlan_type == "dhcp":
                                                            logger.info('Master plugin is false && type is dhcp')
                                                            ret = ansible_playbook_launcher.launch_ansible_playbook_network_dhcp_creation(macvlan_network_dhcp_playbook, macvlan_master_hostname, macvlan_network_name, macvlan_master, PROXY_DATA_FILE)
                                                            if not ret:
                                                                logger.error('FAILED IN MACVLAN network creation2')


        logger.info('Exit')
        return ret


    def configure_macvlan_interface(self, config):    #function for mac-vlan network creation
        """
        This method is used for create macvlan interface list after multus
        :param config :input configuration file
        :return ret :t/f
        """
        logger.info("\n Argument List:" + "\n config:" + str(config))
        ret = False
        if config:
            vlan_playbook = consts.K8_VLAN_INTERFACE_PATH
            logger.info('configure_mac_vlan interfaces')
            noOfNetwroksInMacvlan = config.get(consts.KUBERNETES).get(consts.NETWORK_CREATION_IN_MACVLAN)
            for item1 in noOfNetwroksInMacvlan:
                for key in item1:
                    if key == "Multus_network":
                        multus_network = item1.get("Multus_network")
                        for item2 in multus_network:
                            for key in item2:
                                if key == "CNI_Configuration":
                                    cni_configuration = item2.get("CNI_Configuration")
                                    for item3 in cni_configuration:
                                        for key in item3:
                                            if key == "Macvlan":
                                                macvlan_network1 = item3.get("Macvlan")
                                                for macvlan_networks in macvlan_network1:
                                                    inetfaceDict = macvlan_networks.get("macvlan_networks")
                                                    macvlan_parent_interface = inetfaceDict.get("parent_interface")
                                                    macvlan_vlanid = inetfaceDict.get("vlanid")
                                                    macvlan_ip = inetfaceDict.get("ip")
                                                    macvlan_node_hostname = inetfaceDict.get("hostname")
                                                    logger.info('macvlan_node_hostname is %s', macvlan_node_hostname)
                                                    logger.info('macvlan_parent_interface is %s', macvlan_parent_interface)
                                                    logger.info('macvlan_vlanid is %s', macvlan_vlanid)
                                                    logger.info('macvlan_ip is %s', macvlan_ip)

                                                    ret = ansible_playbook_launcher.launch_ansible_playbook_node_vlantag_interface(
                                                        vlan_playbook, macvlan_node_hostname,
                                                        macvlan_parent_interface,
                                                        macvlan_vlanid, macvlan_ip)
                                                    if not ret:
                                                        logger.error('FAILED IN MACVLAN interface creation')

        logger.info('Exit')
        return ret

    def macvlan_creation_node(self, config, multus_cni_installed):
        """
        This function is used to create the macvlan additional plugin
        """
        multus_cni_installed = True
        logger.info("MACVLAN FOR DYNAMIC NODE ADDITION")
        logger.info('multus_cni_installed %s', multus_cni_installed)
        macvlan_cni = get_macvlan_value(config)
        logger.info('macvlan value n macvlan creation node function:%s', macvlan_cni)
        if multus_cni_installed:
            if macvlan_cni:
                logger.info('CONFIGURING MAC-VLAN')
                Project_name = config.get(consts.KUBERNETES).get(consts.PROJECT_NAME)
                master_node_macvlan = aconf.get_host_master_name(Project_name)
                ret = MultusNetworkingPluginsAddition().configure_macvlan_interface(config)
                ret = MultusNetworkingPluginsAddition().configure_macvlan_networks(
                    config, master_node_macvlan)

            else:
                logger.info('MAC-VLAN CONFIGURATION  EXIT , REASON--> MACVLAN '
                            'IS DISABLED ')
        logger.info('Exit')
        return ret


    def dhcp_installation(self, config):
        logger.info('CONFIGURING DHCP')
        noOfhosts_fornetwork = config.get(consts.KUBERNETES).get(consts.HOSTS)
        for dhcp_host_fornetwork in noOfhosts_fornetwork:
            if dhcp_host_fornetwork != None:
                inetfaceDict_fornetwork = dhcp_host_fornetwork.get("host")
                hostname_fornetwork = inetfaceDict_fornetwork.get("hostname")
                node_type_fornetwork = inetfaceDict_fornetwork.get("node_type")
                if node_type_fornetwork == "minion":
                    macvlan_dhcp_daemon_playbook = consts.K8_DHCP_PATH
                    logger.info('DHCP DAEMON RUNNING')
                    ret = ansible_playbook_launcher.launch_ansible_playbook_dhcp_daemon_creation(
                        macvlan_dhcp_daemon_playbook, hostname_fornetwork)
                    if not ret:
                        logger.info('FAILED IN DHCP DAEMON installation')

        logger.info('Exit')
        return ret

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
import getpass
import logging

from snaps_common.ansible_snaps import ansible_utils
from snaps_k8s.common.consts import consts
from snaps_k8s.common.utils import config_utils

DEFAULT_REPLACE_EXTENSIONS = None

logger = logging.getLogger('ansible_configuration')


def provision_preparation(k8s_conf):
    """
    This method is responsible for setting up this host for k8s provisioning
    :param k8s_conf: the configuration dict object
    """
    node_configs = config_utils.get_node_configs(k8s_conf)
    if node_configs and len(node_configs) > 0:
        for node_config in node_configs:
            host = node_config[consts.HOST_KEY]
            pb_vars = {'hostname': host[consts.HOSTNAME_KEY],
                       'ip': host[consts.IP_KEY]}
            ansible_utils.apply_playbook(consts.SETUP_ETC_HOSTS,
                                         variables=pb_vars)
    else:
        raise Exception('No hosts to deploy - Aborting')


def clean_up_k8(k8s_conf, multus_enabled_str):
    """
    This function is used for clean/Reset the kubernetes cluster
    """
    multus_enabled = str(multus_enabled_str)

    project_name = config_utils.get_project_name(k8s_conf)

    logger.info('EXECUTING CLEAN K8 CLUSTER PLAY')
    pb_vars = {
        'PROJECT_PATH': consts.PROJECT_PATH,
        'KUBESPRAY_PATH': consts.KUBESPRAY_PATH,
        'Project_name': project_name,
    }
    ansible_utils.apply_playbook(consts.K8_CLEAN_UP, variables=pb_vars)

    logger.info("Docker cleanup starts")
    ips = config_utils.get_host_ips(k8s_conf)
    ansible_utils.apply_playbook(consts.K8_DOCKER_CLEAN_UP_ON_NODES, ips)

    host_ips = config_utils.get_hostname_ips_dict(k8s_conf)
    for host_name, ip in host_ips.items():
        pb_vars = {
            'ip': ip,
            'host_name': host_name,
            'Project_name': project_name,
            'multus_enabled': multus_enabled,
        }
        ansible_utils.apply_playbook(consts.K8_REMOVE_NODE_K8, [ip],
                                     variables=pb_vars)

    logger.info('EXECUTING REMOVE PROJECT FOLDER PLAY')
    pb_vars = {
        'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
        'PROJECT_PATH': consts.PROJECT_PATH,
        'Project_name': project_name,
    }
    ansible_utils.apply_playbook(consts.K8_REMOVE_FOLDER, variables=pb_vars)


def start_k8s_install(host_port_map, k8s_conf):
    """
    This function is used for deploy the kubernet cluster
    """
    base_pb_vars = {
        'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
    }
    base_pb_vars.update(config_utils.get_proxy_dict(k8s_conf))

    git_branch = config_utils.get_git_branch(k8s_conf)
    pb_vars = {
        'Git_branch': git_branch,
    }
    pb_vars.update(base_pb_vars)
    ansible_utils.apply_playbook(consts.K8_CLONE_PACKAGES, variables=pb_vars)

    user = getpass.getuser()

    host_name_map = config_utils.get_hostname_ips_dict(k8s_conf)
    __set_hostnames(host_name_map, user, base_pb_vars)
    __configure_docker(host_name_map, host_port_map, user, base_pb_vars)

    docker_repo = config_utils.get_docker_repo(k8s_conf)
    if docker_repo:
        __prepare_docker_repo(docker_repo, host_name_map, base_pb_vars)

    __kubespray(k8s_conf, base_pb_vars)
    __complete_k8s_install(k8s_conf, base_pb_vars)

    logger.info('Completed start_k8s_install()')


def __set_hostnames(host_name_map, user, base_pb_vars):
    ips = list()
    for host_name, ip_val in host_name_map.items():
        ips.append(ip_val)
        ansible_utils.apply_playbook(
            consts.K8_SET_HOSTNAME, hosts_inv=[ip_val], host_user=user,
            variables={'host_name': host_name})

    pb_vars = {
        'APT_ARCHIVES_SRC': consts.APT_ARCHIVES_PATH,
        'APT_CONF_DEST': consts.APT_CONF_DEST
    }
    pb_vars.update(base_pb_vars)
    ansible_utils.apply_playbook(
        consts.K8_SET_PACKAGES, ips, user, password=None,
        variables=pb_vars)


def __configure_docker(host_name_map, host_port_map, user, base_pb_vars):
    ip_val = None
    registry_port = None
    for host_name, ip_val in host_name_map.items():
        registry_port = host_port_map.get(host_name)
        break

    if not ip_val or not registry_port:
        raise Exception('Cannot locate IP or registry port')

    pb_vars = {'registry_port': registry_port,
               'HTTP_PROXY_DEST': consts.HTTP_PROXY_DEST}
    pb_vars.update(base_pb_vars)
    ansible_utils.apply_playbook(
        consts.K8_CONFIG_DOCKER, hosts_inv=[ip_val], host_user=user,
        variables=pb_vars)


def __prepare_docker_repo(docker_repo, host_name_map, base_pb_vars):
    docker_ip = docker_repo.get(consts.IP_KEY)
    docker_port = docker_repo.get(consts.PORT_KEY)
    pb_vars = {
        'docker_ip': docker_ip,
        'docker_port': docker_port,
        'HTTP_PROXY_DEST': consts.HTTP_PROXY_DEST,
    }
    pb_vars.update(base_pb_vars)
    ansible_utils.apply_playbook(consts.K8_PRIVATE_DOCKER,
                                 variables=pb_vars)

    ips = list()
    for host_name, ip in host_name_map.items():
        ips.append(ip)

    pb_vars = {
        'docker_ip': docker_ip,
        'docker_port': docker_port,
        'HTTP_PROXY_DEST': consts.HTTP_PROXY_DEST,
        'DAEMON_FILE': consts.DAEMON_FILE
    }
    pb_vars.update(base_pb_vars)
    ansible_utils.apply_playbook(consts.K8_CONF_DOCKER_REPO, ips,
                                 variables=pb_vars)


def __kubespray(k8s_conf, base_pb_vars):

    project_name = config_utils.get_project_name(k8s_conf)

    pb_vars = {
        'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
        'PROJECT_PATH': consts.PROJECT_PATH,
        'Project_name': project_name,
    }
    ansible_utils.apply_playbook(
        consts.K8_CREATE_INVENTORY_FILE, variables=pb_vars)

    host_name_map = config_utils.get_hostname_ips_dict(k8s_conf)
    for host_name, ip in host_name_map.items():
        pb_vars = {
            'ip': ip,
            'host_name': host_name,
            'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
            'PROJECT_PATH': consts.PROJECT_PATH,
            'Project_name': project_name,
        }
        ansible_utils.apply_playbook(consts.KUBERNETES_NEW_INVENTORY,
                                     variables=pb_vars)

    hosts_t3 = config_utils.get_nodes_ip_name_type(k8s_conf)
    for host_name, ip, node_type in hosts_t3:
        pb_vars = {
            'node_type': node_type,
            'host_name': host_name,
            'PROJECT_PATH': consts.PROJECT_PATH,
            'Project_name': project_name,
        }
        ansible_utils.apply_playbook(consts.KUBERNETES_CREATE_INVENTORY,
                                     variables=pb_vars)

    git_branch = config_utils.get_git_branch(k8s_conf)
    pb_vars = {
        'Git_branch': git_branch,
        'Project_name': project_name,
        'KUBESPRAY_PATH': consts.KUBESPRAY_PATH,
        'PROJECT_PATH': consts.PROJECT_PATH,
    }
    pb_vars.update(base_pb_vars)
    ansible_utils.apply_playbook(consts.K8_CLONE_CODE, variables=pb_vars)

    __enable_cluster_logging(k8s_conf, project_name)

    if k8s_conf[consts.K8S_KEY].get(consts.CPU_ALLOC_KEY):
        ansible_utils.apply_playbook(
            consts.K8_CPU_PINNING_CONFIG,
            variables={'KUBESPRAY_PATH': consts.KUBESPRAY_PATH})

    logger.info('*** EXECUTING INSTALLATION OF KUBERNETES CLUSTER ***')
    service_subnet = config_utils.get_service_subnet(k8s_conf)
    pod_subnet = config_utils.get_pod_subnet(k8s_conf)
    networking_plugin = config_utils.get_networking_plugin(k8s_conf)
    kube_version = config_utils.get_version(k8s_conf)
    pb_vars = {
        'service_subnet': service_subnet,
        'pod_subnet': pod_subnet,
        'networking_plugin': networking_plugin,
        'kube_version': kube_version,
        'Git_branch': git_branch,
        'Project_name': project_name,
        'host_name_map': host_name_map,
        'PROJECT_PATH': consts.PROJECT_PATH,
        'KUBESPRAY_PATH': consts.KUBESPRAY_PATH,
    }
    pb_vars.update(base_pb_vars)
    ansible_utils.apply_playbook(consts.KUBERNETES_SET_LAUNCHER,
                                 variables=pb_vars)


def launch_crd_network(k8s_conf):
    """
    This function is used to create crd network
    """
    master_host_name, master_ip = config_utils.get_first_master_host(k8s_conf)
    logger.info('EXECUTING CRD NETWORK CREATION PLAY. Master ip - %s, '
                'Master Host Name - %s', master_ip, master_host_name)
    pb_vars = {
        'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
        'KUBERNETES_PATH': consts.KUBERNETES_PATH,
    }
    pb_vars.update(config_utils.get_proxy_dict(k8s_conf))
    ansible_utils.apply_playbook(consts.K8_CREATE_CRD_NETWORK, [master_ip],
                                 variables=pb_vars)


def launch_multus_cni(k8s_conf):
    """
    This function is used to launch multus cni
    """
    logger.info('EXECUTING MULTUS CNI PLAY')
    host_tuple_3 = config_utils.get_nodes_ip_name_type(k8s_conf)
    networking_plugin = config_utils.get_networking_plugin(k8s_conf)
    for host_name, ip, node_type in host_tuple_3:
        if node_type == "master":
            pb_vars = {
                'networking_plugin': networking_plugin,
                'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
            }
            pb_vars.update(config_utils.get_proxy_dict(k8s_conf))
            ansible_utils.apply_playbook(consts.K8_MULTUS_SET_MASTER, [ip],
                                         variables=pb_vars)
        elif node_type == "minion":
            ansible_utils.apply_playbook(
                consts.K8_MULTUS_SCP_MULTUS_CNI, [ip],
                variables={
                    'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
                    'networking_plugin': networking_plugin})

            ansible_utils.apply_playbook(
                consts.K8_MULTUS_SET_NODE, [ip],
                variables={'networking_plugin': networking_plugin})


def launch_sriov_cni_configuration(k8s_conf, hosts_data_dict):
    """
    This function is used to launch sriov cni
    """
    minion_list = []
    logger.info('EXECUTING SRIOV CNI PLAY')
    logger.info("INSIDE launch_sriov_cni")
    dpdk_enable = "no"
    project_name = config_utils.get_project_name(k8s_conf)

    inventory_file_path = "{}/{}/{}".format(
        consts.PROJECT_PATH, project_name, "k8s-cluster.yml")
    logger.info('Inventory file path is %s', inventory_file_path)
    networking_plugin = None
    with open(inventory_file_path) as file_handle:
        for line in file_handle:
            if "kube_network_plugin:" in line:
                network_plugin1 = line.split("kube_network_plugin:", 1)[1]
                networking_plugin = network_plugin1.strip(' \t\n\r')
                logger.info('networking_plugin - %s', networking_plugin)
    file_handle.close()

    dpdk_driver = None
    # TODO - REFACTOR ME
    for node in hosts_data_dict:
        for key in node:
            if "Sriov" == key:
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
                        pb_vars = {
                            'host_name': hostname,
                            'sriov_intf': sriov_intf,
                            'networking_plugin': networking_plugin,
                        }
                        ansible_utils.apply_playbook(
                            consts.K8_SRIOV_ENABLE, [hostname],
                            variables=pb_vars)
    pb_vars = config_utils.get_proxy_dict(k8s_conf)
    pb_vars.append({'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR})
    ansible_utils.apply_playbook(consts.K8_SRIOV_CNI_BUILD, variables=pb_vars)

    logger.info('DPDK flag is %s', dpdk_enable)
    if dpdk_enable == "yes":
        pb_vars = config_utils.get_proxy_dict(k8s_conf)
        pb_vars.append({'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR})
        ansible_utils.apply_playbook(consts.K8_SRIOV_DPDK_CNI,
                                     variables=pb_vars)

    master_nodes_tuple_3 = config_utils.get_master_nodes_ip_name_type(k8s_conf)
    for hostname, ip, host_type in master_nodes_tuple_3:
        logger.info('INSTALLING SRIOV BIN ON MASTER')
        ansible_utils.apply_playbook(
            consts.K8_SRIOV_CNI_BIN_INST, [ip],
            variables={'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR})

        if dpdk_enable == "yes":
            logger.info('INSTALLING SRIOV DPDK BIN ON MASTER')
            ansible_utils.apply_playbook(
                consts.K8_SRIOV_DPDK_CNI_BIN_INST, [ip],
                variables={'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR})

    for host_name in minion_list:
        logger.info('Executing for  minion %s', host_name)
        logger.info('INSTALLING SRIOV BIN ON WORKER nodes')
        ansible_utils.apply_playbook(
            consts.K8_SRIOV_DPDK_CNI_BIN_INST, [host_name],
            variables={'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR})
        if dpdk_enable == "yes":
            logger.info('INSTALLING SRIOV DPDK BIN ON WORKERS')
            ansible_utils.apply_playbook(
                consts.K8_SRIOV_DPDK_DRIVER_LOAD, [host_name],
                variables={'dpdk_driver': dpdk_driver})

            ansible_utils.apply_playbook(
                consts.K8_SRIOV_DPDK_CNI_BIN_INST, [host_name],
                variables={'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR})


def launch_sriov_network_creation(k8s_conf, hosts_data_dict):
    master_host, ip = config_utils.get_first_master_host(k8s_conf)
    # TODO - REFACTOR ME
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
                        master_plugin = network.get(consts.MASTER_PLUGIN_KEY)
                        if dpdk_enable == "yes":
                            logger.info(
                                'SRIOV NETWORK CREATION STARTED USING DPDK '
                                'DRIVER')
                            pb_vars = {
                                'intf': sriov_intf,
                                'network_name': sriov_nw_name,
                                'dpdk_driver': dpdk_driver,
                                'dpdk_tool': dpdk_tool,
                                'node_hostname': node_hostname,
                            }
                            ansible_utils.apply_playbook(
                                consts.K8_SRIOV_DPDK_CR_NW, [master_host],
                                variables=pb_vars)

                        if dpdk_enable == "no":
                            if host == "host-local":
                                logger.info(
                                    'SRIOV NETWORK CREATION STARTED USING '
                                    'KERNEL DRIVER WITH IPAM host-local')

                                pb_vars = {
                                    'host_name': master_host,
                                    'intf': sriov_intf,
                                    'network_name': sriov_nw_name,
                                    'rangeStart': range_start,
                                    'rangeEnd': range_end,
                                    'subnet': sriov_subnet,
                                    'gateway': sriov_gateway,
                                    'masterPlugin': master_plugin,
                                }
                                ansible_utils.apply_playbook(
                                    consts.K8_SRIOV_CR_NW, [master_host],
                                    variables=pb_vars)

                            if host == consts.DHCP_TYPE:
                                logger.info(
                                    'SRIOV NETWORK CREATION STARTED USING '
                                    'KERNEL DRIVER WITH IPAM host-dhcp')
                                pb_vars = {
                                    'intf': sriov_intf,
                                    'network_name': sriov_nw_name,
                                }
                                pb_vars.update(
                                    config_utils.get_proxy_dict(k8s_conf))
                                ansible_utils.apply_playbook(
                                    consts.K8_SRIOV_DHCP_CR_NW, [master_host],
                                    variables=pb_vars)


def create_default_network(k8s_conf):
    default_network = config_utils.get_default_network(k8s_conf)
    network_name = default_network.get(consts.NETWORK_NAME_KEY)
    if not network_name:
        raise Exception('no network name in [%s]', default_network)

    master_plugin = default_network.get(consts.MASTER_PLUGIN_KEY)
    networking_plugin = config_utils.get_networking_plugin(k8s_conf)
    pb_vars = {
        'networkName': network_name,
        'masterPlugin': master_plugin,
        'networking_plugin': networking_plugin
    }
    pb_vars.update(config_utils.get_proxy_dict(k8s_conf))
    ips = config_utils.get_master_node_ips(k8s_conf)
    ansible_utils.apply_playbook(
        consts.K8_CREATE_DEFAULT_NETWORK, ips, variables=pb_vars)


def create_flannel_interface(k8s_conf):
    logger.info('EXECUTING FLANNEL INTERFACE CREATION PLAY IN CREATE FUNC')
    flannel_cfgs = config_utils.get_multus_cni_flannel_cfgs(k8s_conf)
    if flannel_cfgs:
        network_name = None
        master_plugin = None
        ip = None

        if consts.FLANNEL_NET_TYPE not in flannel_cfgs:
            raise Exception('CNI config not of type %s',
                            consts.FLANNEL_NET_TYPE)

        for key, host_detail_cfgs in flannel_cfgs.items():
            for flannel_details in host_detail_cfgs:
                host_details = flannel_details.get(
                    consts.FLANNEL_NET_DTLS_KEY)
                network_name = host_details.get(consts.NETWORK_NAME_KEY)
                network = host_details.get(consts.NETWORK_KEY)
                cidr = host_details.get(consts.SUBNET_KEY)
                master_plugin = host_details.get(consts.MASTER_PLUGIN_KEY)
                master_hosts_t3 = config_utils.get_master_nodes_ip_name_type(
                    k8s_conf)
                for host_name, ip, node_type in master_hosts_t3:
                    pb_vars = {
                        'network': network,
                        'cidr': cidr,
                    }
                    ansible_utils.apply_playbook(
                        consts.K8_CONF_FLANNEL_DAEMON_AT_MASTER, [ip],
                        variables=pb_vars)

                    pb_vars = {
                        'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
                        'network': network,
                        'ip': ip,
                    }
                    ansible_utils.apply_playbook(
                        consts.K8_CONF_COPY_FLANNEL_CNI, [ip],
                        variables=pb_vars)
        # TODO/FIXME - This logic appears brittle and possibly flawed
        if not ip:
            logger.info('Flannel CNI not configured')
        else:
            pb_vars = {
                'networkName': network_name,
                'masterPlugin': master_plugin,
                'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
            }
            pb_vars.update(config_utils.get_proxy_dict(k8s_conf))
            ansible_utils.apply_playbook(
                consts.K8_CONF_FLANNEL_INTF_CREATION_AT_MASTER, [ip],
                variables=pb_vars)


def create_weave_interface(k8s_conf, weave_detail):
    """
    This function is used to create weave interace and network
    """
    logger.info('CREATING WEAVE NETWORK')
    network_dict = weave_detail.get(consts.WEAVE_NET_DTLS_KEY)
    network_name = network_dict.get(consts.NETWORK_NAME_KEY)
    subnet = network_dict.get(consts.SUBNET_KEY)
    master_plugin = network_dict.get(consts.MASTER_PLUGIN_KEY)

    master_host_tuple_3 = config_utils.get_master_nodes_ip_name_type(k8s_conf)
    for host_name, ip, node_type in master_host_tuple_3:
        pb_vars = {
            'ip': ip,
            'subnet': subnet,
            'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
        }
        ansible_utils.apply_playbook(
            consts.K8_CONF_COPY_WEAVE_CNI, [ip], variables=pb_vars)

    master_host, master_ip = config_utils.get_first_master_host(k8s_conf)
    logger.info('CREATING WEAVE NETWORKS on %s|%s', master_host, master_ip)
    pb_vars = {
        'networkName': network_name,
        'subnet': subnet,
        'masterPlugin': master_plugin,
        'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
    }
    pb_vars.update(config_utils.get_proxy_dict(k8s_conf))
    ansible_utils.apply_playbook(
        consts.K8_CONF_WEAVE_NETWORK_CREATION, [master_ip], variables=pb_vars)

    ips = config_utils.get_minion_node_ips(k8s_conf)
    networking_plugin = config_utils.get_networking_plugin(k8s_conf)
    ansible_utils.apply_playbook(
        consts.K8_CONF_FILES_DELETION_AFTER_MULTUS, ips,
        variables={'networking_plugin': networking_plugin})


def clean_up_metrics_server(k8s_conf):
    logger.info("clean_up_metrics_server")
    master_nodes_tuple_3 = config_utils.get_master_nodes_ip_name_type(k8s_conf)
    for host_name, ip, node_type in master_nodes_tuple_3:
        ansible_utils.apply_playbook(
            consts.K8_METRICS_SERVER_CLEAN, [host_name],
            variables=config_utils.get_proxy_dict(k8s_conf))
        break


def launch_ceph_kubernetes(k8s_conf):
    """
    This function is used for deploy the ceph
    """
    proxy_dict = config_utils.get_proxy_dict(k8s_conf)
    node_confs = config_utils.get_node_configs(k8s_conf)
    ceph_hosts = config_utils.get_ceph_vol(k8s_conf)

    if node_confs:
        for host_conf in node_confs:
            node_type = host_conf[consts.HOST_KEY][consts.NODE_TYPE_KEY]
            if node_type == "master":
                ansible_utils.apply_playbook(
                    consts.KUBERNETES_CEPH_DELETE_SECRET)
                break

    controller_host_name = None
    control_ip = None
    flag_second_storage = None

    # TODO - REFACTOR ME
    if ceph_hosts:
        for ceph_host in ceph_hosts:
            host_conf = ceph_host[consts.HOST_KEY]
            host_ip = host_conf[consts.IP_KEY]
            host_name = host_conf[consts.HOSTNAME_KEY]
            pb_vars = {
                'host_name': host_name,
                'host_ip': host_ip,
            }
            ansible_utils.apply_playbook(consts.KUBERNETES_CEPH_VOL_FIRST,
                                         [host_ip], variables=pb_vars)

            control_ip = ceph_host.get(consts.HOST_KEY).get(consts.IP_KEY)
            controller_host_name = host_name
            for inner_ceph_host_cfg in ceph_hosts:
                host = inner_ceph_host_cfg[consts.HOST_KEY]
                user_id = host[consts.USER_KEY]
                passwd = host[consts.PASSWORD_KEY]
                osd_host_name = host[consts.HOSTNAME_KEY]
                osd_ip = host[consts.IP_KEY]
                pb_vars = {
                    'osd_host_name': osd_host_name,
                    'user_id': user_id,
                    'passwd': passwd,
                    'osd_ip': osd_ip,
                }
                ansible_utils.apply_playbook(
                    consts.KUBERNETES_CEPH_VOL, [host_ip],
                    variables=pb_vars)

        for ceph_host in ceph_hosts:
            host_conf = ceph_host[consts.HOST_KEY]
            host_name = host_conf[consts.HOSTNAME_KEY]
            pb_vars = {
                'host_name': host_name,
                'master_host_name': controller_host_name,
            }
            pb_vars.update(proxy_dict)
            ansible_utils.apply_playbook(consts.CEPH_DEPLOY, [host_name],
                                         variables=pb_vars)

        ansible_utils.apply_playbook(
            consts.CEPH_MON, [controller_host_name], variables=proxy_dict)

        # TODO - REFACTOR ME
        for ceph_host in ceph_hosts:
            host_name = ceph_host.get(consts.HOST_KEY).get(consts.HOSTNAME_KEY)
            node_type = ceph_host.get(consts.HOST_KEY).get(
                consts.NODE_TYPE_KEY)

            flag_second_storage = 0
            if node_type == "ceph_osd":
                flag_second_storage = 1
                second_storage = ceph_hosts.get(consts.HOST_KEY).get(
                    consts.STORAGE_TYPE_KEY)
                logger.info("secondstorage is")
                if second_storage:
                    for storage in second_storage:
                        pb_vars = {
                            'host_name': host_name,
                            'master_host_name': controller_host_name,
                            'storage': storage,
                        }
                        pb_vars.update(proxy_dict)
                        ansible_utils.apply_playbook(
                            consts.KUBERNETES_CEPH_STORAGE, [host_name],
                            variables=pb_vars)

        for ceph_host in ceph_hosts:
            host_name = ceph_host[consts.HOST_KEY][consts.HOSTNAME_KEY]
            pb_vars = {
                'host_name': host_name,
                'master_host_name': controller_host_name,
            }
            pb_vars.update(proxy_dict)
            ansible_utils.apply_playbook(consts.CEPH_DEPLOY_ADMIN, [host_name],
                                         variables=pb_vars)

        pb_vars = {
            'master_host_name': controller_host_name,
        }
        pb_vars.update(proxy_dict)
        ansible_utils.apply_playbook(consts.CEPH_MDS, [controller_host_name],
                                     variables=pb_vars)

    # TODO - REFACTOR ME
    if node_confs:
        count = 0
        for i in range(len(node_confs)):
            host_conf = node_confs[i].get(consts.HOST_KEY)
            node_type = host_conf.get(consts.NODE_TYPE_KEY)
            logger.info(node_type)
            if node_type == "master" and count == 0:
                count = count + 1  # changes for ha
                hostname = host_conf.get(consts.HOSTNAME_KEY)
                logger.info(consts.KUBERNETES_CEPH_VOL2)
                logger.info("flag secondstorage is")
                logger.info(flag_second_storage)
                if 1 == flag_second_storage:
                    ceph_claims = ceph_hosts[i].get(consts.HOST_KEY).get(
                        consts.CEPH_CLAIMS_KEY)
                    for j in range(len(ceph_claims)):
                        ceph_claim_name = ceph_claims[j].get(
                            consts.CLAIM_PARAMS_KEY).get(
                            consts.CEPH_CLAIM_NAME_KEY)
                        logger.info('ceph_claim name is %s', ceph_claim_name)
                        ceph_storage_size = ceph_claims[j].get(
                            consts.CLAIM_PARAMS_KEY).get(
                            consts.CEPH_STORAGE_KEY)
                        logger.info('ceph_storage_size is %s',
                                    ceph_storage_size)
                        pb_vars = {
                            'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
                            'ceph_storage_size': ceph_storage_size,
                            'ceph_claim_name': ceph_claim_name,
                            'KUBERNETES_PATH': consts.KUBERNETES_PATH,
                            'controller_host_name': controller_host_name,
                            'ceph_controller_ip': control_ip,
                        }
                        pb_vars.update(proxy_dict)
                        ansible_utils.apply_playbook(
                            consts.KUBERNETES_CEPH_VOL2, [hostname],
                            variables=pb_vars)


def launch_persitent_volume_kubernetes(k8s_conf):
    """
    This function is used for deploy the persistent_volume
    """
    persistent_vol = config_utils.get_host_vol(k8s_conf)
    if persistent_vol:
        host_name, ip = config_utils.get_first_master_host(k8s_conf)
        for vol in persistent_vol:
            storage_size = vol.get(consts.CLAIM_PARAMS_KEY).get(
                consts.STORAGE_KEY)
            claim_name = vol.get(consts.CLAIM_PARAMS_KEY).get(
                consts.CLAIM_NAME_KEY)
            pb_vars = {
                'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
                'KUBERNETES_PATH': consts.KUBERNETES_PATH,
                'host_name': host_name,
                'storage_size': storage_size,
                'claim_name': claim_name,
            }
            pb_vars.update(config_utils.get_proxy_dict(k8s_conf))
            ansible_utils.apply_playbook(
                consts.KUBERNETES_PERSISTENT_VOL, [host_name],
                variables=pb_vars)


def get_host_master_name(k8s_conf):
    """
    Returns the first hostname of type 'master'
    :param k8s_conf: the k8s configuration dict
    :return: the first master hostname
    """
    if ('kubernetes' in k8s_conf
            and 'node_configuration' in k8s_conf['kubernetes']):
        host_confs = k8s_conf['kubernetes']['node_configuration']
        for host_conf in host_confs:
            if host_conf['host']['node_type'] == 'master':
                return host_conf['host']['hostname']

    logger.warn('Unable to access the master host with conf %s', k8s_conf)


def __enable_cluster_logging(k8s_conf, project_name):
    """
    This function is used to enable logging in cluster
    :param k8s_conf: k8s config
    :param project_name: Project name
    """
    enable_logging = k8s_conf[consts.K8S_KEY][consts.ENABLE_LOG_KEY]
    if enable_logging is not None:
        if enable_logging is not True and enable_logging is not False:
            raise Exception('Either enabled logging or disabled logging')

        if enable_logging:
            value = "True"
            log_level = k8s_conf[consts.K8S_KEY][consts.LOG_LEVEL_KEY]
            if (log_level != "fatal" and log_level != "warning"
                    and log_level != "info" and log_level != "debug"
                    and log_level != "critical"):
                raise Exception('Invalid log_level')
            logging_port = k8s_conf[consts.K8S_KEY][consts.LOG_PORT_KEY]
            pb_vars = {
                "logging": value,
                'Project_name': project_name,
                "log_level": log_level,
                "file_path": consts.LOG_FILE_PATH,
                "logging_port": logging_port,
                "KUBESPRAY_PATH": consts.KUBESPRAY_PATH,
                "PROJECT_PATH": consts.PROJECT_PATH,
            }
            pb_vars.update(config_utils.get_proxy_dict(k8s_conf))
            ansible_utils.apply_playbook(consts.K8_LOGGING_PLAY,
                                         variables=pb_vars)
    else:
        logger.warn('Logging not configured')


def __complete_k8s_install(k8s_conf, base_pb_vars):

    __install_kubectl(k8s_conf)
    __label_nodes(k8s_conf)
    __config_master(k8s_conf, base_pb_vars)


def __install_kubectl(k8s_conf):
    """
    This function is used to install kubectl at bootstrap node
    """
    lb_ip = "127.0.0.1"
    ha_configuration = config_utils.get_ha_config(k8s_conf)
    if ha_configuration:
        for ha_config_list_data in ha_configuration:
            lb_ip = ha_config_list_data.get(consts.HA_API_EXT_LB_KEY).get("ip")

    logger.info("Load balancer ip %s", lb_ip)

    host_name, ip = config_utils.get_first_master_host(k8s_conf)
    if not ip or not host_name:
        raise Exception('Unable to locate IP or hostname')

    # TODO/FIXME - need to add HA support
    # ha_enabled = config_utils.get_ha_config(k8s_conf) is not None
    ha_enabled = False
    project_name = config_utils.get_project_name(k8s_conf)

    pb_vars = {
        'ip': ip,
        'host_name': host_name,
        'ha_enabled': ha_enabled,
        'Project_name': project_name,
        'lb_ip': lb_ip,
        'PROJECT_PATH': consts.PROJECT_PATH,
        'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
    }
    pb_vars.update(config_utils.get_proxy_dict(k8s_conf))
    ansible_utils.apply_playbook(consts.K8_KUBECTL_INSTALLATION,
                                 variables=pb_vars)


def __config_master(k8s_conf, base_pb_vars):
    master_nodes_t3 = config_utils.get_master_nodes_ip_name_type(k8s_conf)
    for host_name, ip, node_type in master_nodes_t3:
        pb_vars = {
            'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
        }
        if node_type == "master":
            ansible_utils.apply_playbook(consts.KUBERNETES_WEAVE_SCOPE,
                                         variables=pb_vars)
            pb_vars = {
                'host_name': host_name,
            }
            pb_vars.update(base_pb_vars)
            ansible_utils.apply_playbook(
                consts.KUBERNETES_KUBE_PROXY, [host_name], variables=pb_vars)
            logger.info('Started KUBE PROXY')


def __label_nodes(k8s_conf):
    node_cfgs = config_utils.get_node_configs(k8s_conf)
    for node_cfg in node_cfgs:
        node = node_cfg[consts.HOST_KEY]
        label_key = node.get(consts.LABEL_KEY)
        hostname = node.get(consts.HOSTNAME_KEY)
        label_value = node.get(consts.LBL_VAL_KEY)
        pb_vars = {
            'hostname': hostname,
            'label_key': label_key,
            'label_value': label_value,
        }
        ansible_utils.apply_playbook(
            consts.K8_NODE_LABELING, variables=pb_vars)


def delete_default_weave_interface(k8s_conf):
    """
    This function is used to delete default weave interface
    """
    logger.info('EXECUTING DEFAULT WEAVE INTERFACE DELETION PLAY')
    if config_utils.get_networking_plugin(k8s_conf) != consts.WEAVE_TYPE:
        logger.info('DEFAULT NETWORKING PLUGIN IS NOT WEAVE, '
                    'NO NEED TO CLEAN WEAVE')
        return

    network_name = config_utils.get_default_network(
        k8s_conf)[consts.NETWORK_NAME_KEY]
    pb_vars = {
        'node_type': consts.NODE_TYPE_MASTER,
        'networkName': network_name,
        'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
    }
    ansible_utils.apply_playbook(consts.K8_DELETE_WEAVE_INTERFACE,
                                 variables=pb_vars)

    ips = config_utils.get_minion_node_ips(k8s_conf)
    for ip in ips:
        pb_vars = {
            'ip': ip,
            'node_type': consts.NODE_TYPE_MINION,
            'networkName': network_name,
            'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
        }
        ansible_utils.apply_playbook(consts.K8_DELETE_WEAVE_INTERFACE,
                                     variables=pb_vars)


def delete_flannel_interfaces(k8s_conf):
    """
    This function is used to delete flannel interfaces
    """
    logger.info('EXECUTING FLANNEL INTERFACE DELETION PLAY')
    multus_flannel_cfgs = config_utils.get_multus_cni_flannel_cfgs(k8s_conf)

    for multus_flannel_cfg in multus_flannel_cfgs[consts.FLANNEL_NET_TYPE]:
        hostdetails = multus_flannel_cfg.get(consts.FLANNEL_NET_DTLS_KEY)
        network_name = hostdetails.get(consts.NETWORK_NAME_KEY)

        pb_vars = {
            'node_type': consts.NODE_TYPE_MASTER,
            'networkName': network_name,
            'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
        }
        master_host_name, master_ip = config_utils.get_first_master_host(
            k8s_conf)
        if master_ip:
            ansible_utils.apply_playbook(
                consts.K8_DELETE_FLANNEL_INTERFACE, [master_ip],
                variables=pb_vars)


def delete_weave_interface(k8s_conf):
    """
    This function is used to delete weave interface
    """
    logger.info('EXECUTING WEAVE INTERFACE DELETION PLAY')
    weave_details = config_utils.get_multus_weave_details(k8s_conf)
    master_host_name, master_ip = config_utils.get_first_master_host(k8s_conf)
    logger.info('DELETING WEAVE INTERFACE.. Master ip: %s, Master Host '
                'Name: %s', master_ip, master_host_name)

    for weave_detail in weave_details:
        network_name = weave_detail.get(consts.NETWORK_NAME_KEY)
        pb_vars = {
            'node_type': consts.NODE_TYPE_MASTER,
            'networkName': network_name,
            'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
        }
        ansible_utils.apply_playbook(consts.K8_DELETE_WEAVE_INTERFACE,
                                     variables=pb_vars)

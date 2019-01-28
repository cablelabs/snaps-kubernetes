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


def clean_up_k8(k8s_conf, multus_enabled_str, ceph_hosts):
    """
    This function is used for clean/Reset the kubernetes cluster
    """
    multus_enabled = str(multus_enabled_str)

    project_name = config_utils.get_project_name(k8s_conf)

    logger.info('EXECUTING CLEAN K8 CLUSTER PLAY')
    pb_vars = {
        'KUBESPRAY_PATH': config_utils.get_kubespray_dir(k8s_conf),
        'SRC_PACKAGE_PATH': config_utils.get_artifact_dir(k8s_conf),
        'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(k8s_conf),
        'CEPH_HOSTS': ceph_hosts,
    }
    ansible_utils.apply_playbook(consts.K8_CLEAN_UP, variables=pb_vars)

    logger.info("Docker cleanup starts")
    ips = config_utils.get_host_ips(k8s_conf)
    ansible_utils.apply_playbook(
        consts.K8_DOCKER_CLEAN_UP_ON_NODES, ips, consts.NODE_USER)

    host_ips = config_utils.get_hostname_ips_dict(k8s_conf)
    for host_name, ip in host_ips.items():
        pb_vars = {
            'ip': ip,
            'host_name': host_name,
            'Project_name': project_name,
            'multus_enabled': multus_enabled,
        }
        ansible_utils.apply_playbook(
            consts.K8_REMOVE_NODE_K8, [ip], consts.NODE_USER,
            variables=pb_vars)

    logger.info('EXECUTING REMOVE PROJECT FOLDER PLAY')
    pb_vars = {
        'SRC_PACKAGE_PATH': config_utils.get_artifact_dir(k8s_conf),
        'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(k8s_conf),
        'Project_name': project_name,
    }
    ansible_utils.apply_playbook(consts.K8_REMOVE_FOLDER, variables=pb_vars)


def start_k8s_install(k8s_conf):
    """
    This function is used for deploy the kubernet cluster
    """
    logger.info('Starting Kubernetes installation')

    base_pb_vars = {
        'SRC_PACKAGE_PATH': config_utils.get_artifact_dir(k8s_conf),
    }
    base_pb_vars.update(config_utils.get_proxy_dict(k8s_conf))

    __prepare_docker(k8s_conf, base_pb_vars)
    __kubespray(k8s_conf, base_pb_vars)
    __complete_k8s_install(k8s_conf, base_pb_vars)

    logger.info('Completed Kubernetes installation')


def __set_hostnames(k8s_conf, base_pb_vars):
    host_name_map = config_utils.get_hostname_ips_dict(k8s_conf)
    ips = list()
    for host_name, ip_val in host_name_map.items():
        ips.append(ip_val)
        ansible_utils.apply_playbook(
            consts.K8_SET_HOSTNAME, [ip_val], consts.NODE_USER,
            variables={'host_name': host_name})

    pb_vars = {
        'APT_ARCHIVES_SRC': consts.NODE_APT_ARCH_PATH,
        'APT_CONF_DEST': consts.NODE_APT_CONF_DEST
    }
    pb_vars.update(base_pb_vars)
    ansible_utils.apply_playbook(
        consts.K8_SET_PACKAGES, ips, consts.NODE_USER, password=None,
        variables=pb_vars)


def __configure_docker(k8s_conf, base_pb_vars):
    host_name_map = config_utils.get_hostname_ips_dict(k8s_conf)
    host_port_map = config_utils.get_host_reg_port_dict(k8s_conf)

    ip_val = None
    registry_port = None
    for host_name, ip_val in host_name_map.items():
        registry_port = host_port_map.get(host_name)
        break

    if not ip_val or not registry_port:
        raise Exception('Cannot locate IP or registry port')

    pb_vars = {'registry_port': registry_port,
               'HTTP_PROXY_DEST': consts.NODE_HTTP_PROXY_DEST}
    pb_vars.update(base_pb_vars)
    ansible_utils.apply_playbook(
        consts.K8_CONFIG_DOCKER, [ip_val], consts.NODE_USER,
        variables=pb_vars)


def __prepare_docker_repo(k8s_conf, base_pb_vars):
    docker_repo = config_utils.get_docker_repo(k8s_conf)
    if docker_repo:
        docker_ip = docker_repo.get(consts.IP_KEY)
        docker_port = docker_repo.get(consts.PORT_KEY)
        pb_vars = {
            'docker_ip': docker_ip,
            'docker_port': docker_port,
            'HTTP_PROXY_DEST': consts.NODE_HTTP_PROXY_DEST,
        }
        pb_vars.update(base_pb_vars)
        ansible_utils.apply_playbook(consts.K8_PRIVATE_DOCKER,
                                     variables=pb_vars)

        host_name_map = config_utils.get_hostname_ips_dict(k8s_conf)
        ips = list()
        for host_name, ip in host_name_map.items():
            ips.append(ip)

        pb_vars = {
            'docker_ip': docker_ip,
            'docker_port': docker_port,
            'HTTP_PROXY_DEST': consts.NODE_HTTP_PROXY_DEST,
            'DAEMON_FILE': consts.NODE_DOCKER_DAEMON_FILE
        }
        pb_vars.update(base_pb_vars)
        ansible_utils.apply_playbook(
            consts.K8_CONF_DOCKER_REPO, ips, consts.NODE_USER,
            variables=pb_vars)


def __prepare_docker(k8s_conf, base_pb_vars):
    git_branch = config_utils.get_git_branch(k8s_conf)
    pb_vars = {
        'Git_branch': git_branch,
    }
    pb_vars.update(base_pb_vars)
    ansible_utils.apply_playbook(consts.K8_CLONE_PACKAGES, variables=pb_vars)

    __set_hostnames(k8s_conf, base_pb_vars)
    __configure_docker(k8s_conf, base_pb_vars)
    __prepare_docker_repo(k8s_conf, base_pb_vars)


def __kubespray(k8s_conf, base_pb_vars):

    pb_vars = {
        'SRC_PACKAGE_PATH': config_utils.get_artifact_dir(k8s_conf),
        'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(k8s_conf),
    }
    ansible_utils.apply_playbook(
        consts.K8_CREATE_INVENTORY_FILE, variables=pb_vars)

    host_name_map = config_utils.get_hostname_ips_dict(k8s_conf)
    for host_name, ip in host_name_map.items():
        pb_vars = {
            'ip': ip,
            'host_name': host_name,
            'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(
                k8s_conf),
        }
        pb_vars.update(config_utils.get_proxy_dict(k8s_conf))
        ansible_utils.apply_playbook(consts.KUBERNETES_NEW_INVENTORY,
                                     variables=pb_vars)

    hosts_t3 = config_utils.get_nodes_ip_name_type(k8s_conf)
    for host_name, ip, node_type in hosts_t3:
        pb_vars = {
            'node_type': node_type,
            'host_name': host_name,
            'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(
                k8s_conf),
        }
        ansible_utils.apply_playbook(consts.KUBERNETES_CREATE_INVENTORY,
                                     variables=pb_vars)

    pb_vars = {
        'Git_branch': config_utils.get_git_branch(k8s_conf),
        'KUBESPRAY_PATH': config_utils.get_kubespray_dir(k8s_conf),
        'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(
            k8s_conf),
    }
    pb_vars.update(base_pb_vars)
    ansible_utils.apply_playbook(consts.K8_CLONE_CODE, variables=pb_vars)

    __enable_cluster_logging(k8s_conf)

    if config_utils.is_cpu_alloc(k8s_conf):
        ansible_utils.apply_playbook(
            consts.K8_CPU_PINNING_CONFIG,
            variables={'KUBESPRAY_PATH': config_utils.get_kubespray_dir(
                k8s_conf)})

    # Setup HA load balancer
    __ha_configuration(k8s_conf)

    logger.info('*** EXECUTING INSTALLATION OF KUBERNETES CLUSTER ***')
    host_name_map = config_utils.get_hostname_ips_dict(k8s_conf)
    pb_vars = {
        'service_subnet': config_utils.get_service_subnet(k8s_conf),
        'pod_subnet': config_utils.get_pod_subnet(k8s_conf),
        'networking_plugin': config_utils.get_networking_plugin(k8s_conf),
        'kube_version': config_utils.get_version(k8s_conf),
        'Git_branch': config_utils.get_git_branch(k8s_conf),
        'host_name_map': host_name_map,
        'KUBESPRAY_PATH': config_utils.get_kubespray_dir(k8s_conf),
        'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(
            k8s_conf),
    }
    pb_vars.update(base_pb_vars)
    ansible_utils.apply_playbook(consts.KUBERNETES_SET_LAUNCHER,
                                 variables=pb_vars)

    kubespray_pb = "{}/{}".format(config_utils.get_kubespray_dir(k8s_conf),
                                  consts.KUBESPRAY_PB_REL_LOC)
    inv_filename = "{}/kubespray/inventory/sample/inventory.cfg".format(
        config_utils.get_kubespray_dir(k8s_conf))
    logger.info('Calling Kubespray with inventory %s', inv_filename)
    from ansible.module_utils import ansible_release
    version = ansible_release.__version__
    v_tok = version.split('.')
    ansible_utils.apply_playbook(
        kubespray_pb, host_user=consts.NODE_USER, variables={
            "ansible_version": {
                "full": "{}.{}".format(v_tok[0], v_tok[1]),
                "major": v_tok[0],
                "minor": v_tok[1],
                "revision": v_tok[2],
                "string": "{}.{}.{}.0".format(v_tok[0], v_tok[1], v_tok[2])
            },
        },
        inventory_file=inv_filename, become_user='root')


def launch_crd_network(k8s_conf):
    """
    This function is used to create crd network
    """
    master_host_name, master_ip = config_utils.get_first_master_host(k8s_conf)
    logger.info('EXECUTING CRD NETWORK CREATION PLAY. Master ip - %s, '
                'Master Host Name - %s', master_ip, master_host_name)
    pb_vars = {
        'SRC_PACKAGE_PATH': config_utils.get_artifact_dir(k8s_conf),
        'KUBERNETES_PATH': consts.NODE_K8S_PATH,
        'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(k8s_conf),
    }
    pb_vars.update(config_utils.get_proxy_dict(k8s_conf))
    ansible_utils.apply_playbook(consts.K8_CREATE_CRD_NETWORK, [master_ip],
                                 consts.NODE_USER, variables=pb_vars)


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
                'SRC_PACKAGE_PATH': config_utils.get_artifact_dir(k8s_conf),
            }
            pb_vars.update(config_utils.get_proxy_dict(k8s_conf))
            ansible_utils.apply_playbook(consts.K8_MULTUS_SET_MASTER, [ip],
                                         consts.NODE_USER, variables=pb_vars)
        elif node_type == "minion":
            ansible_utils.apply_playbook(
                consts.K8_MULTUS_SCP_MULTUS_CNI, [ip], consts.NODE_USER,
                variables={
                    'SRC_PACKAGE_PATH': config_utils.get_artifact_dir(
                        k8s_conf),
                    'networking_plugin': networking_plugin})

            ansible_utils.apply_playbook(
                consts.K8_MULTUS_SET_NODE, [ip], consts.NODE_USER,
                variables={
                    'networking_plugin': networking_plugin,
                    'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(
                        k8s_conf),
                })


def launch_sriov_cni_configuration(k8s_conf):
    """
    This function is used to launch sriov cni
    """
    logger.info('EXECUTING SRIOV CNI PLAY')

    networking_plugin = config_utils.get_networking_plugin(k8s_conf)
    dpdk_driver = 'vfio-pci'
    dpdk_enable = False

    sriov_cfgs = config_utils.get_multus_cni_sriov_cfgs(k8s_conf)
    for sriov_cfg in sriov_cfgs:
        sriov_host = sriov_cfg[consts.HOST_KEY]

        # for sriov_net in sriov_hosts:
        hostname = sriov_host[consts.HOSTNAME_KEY]

        for sriov_net in sriov_host[consts.SRIOV_NETWORKS_KEY]:
            dpdk_enable = config_utils.bool_val(
                sriov_net.get(consts.SRIOV_DPDK_ENABLE_KEY, None))
            pb_vars = {
                'host_name': hostname,
                'sriov_intf': sriov_net[consts.SRIOV_INTF_KEY],
                'networking_plugin': networking_plugin,
                'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(
                    k8s_conf),
            }
            ansible_utils.apply_playbook(
                consts.K8_SRIOV_ENABLE, [hostname], consts.NODE_USER,
                variables=pb_vars)

    pb_vars = config_utils.get_proxy_dict(k8s_conf)
    pb_vars.update(
        {'SRC_PACKAGE_PATH': config_utils.get_artifact_dir(k8s_conf)})
    ansible_utils.apply_playbook(consts.K8_SRIOV_CNI_BUILD, variables=pb_vars)

    logger.info('DPDK flag is %s', dpdk_enable)
    if dpdk_enable is True:
        pb_vars = config_utils.get_proxy_dict(k8s_conf)
        pb_vars.update(
            {'SRC_PACKAGE_PATH': config_utils.get_artifact_dir(k8s_conf)})
        ansible_utils.apply_playbook(consts.K8_SRIOV_DPDK_CNI,
                                     variables=pb_vars)

    master_nodes_tuple_3 = config_utils.get_master_nodes_ip_name_type(k8s_conf)
    for hostname, ip, host_type in master_nodes_tuple_3:
        logger.info('INSTALLING SRIOV BIN ON MASTER')
        ansible_utils.apply_playbook(
            consts.K8_SRIOV_CNI_BIN_INST, [ip], consts.NODE_USER,
            variables={
                'SRC_PACKAGE_PATH': config_utils.get_artifact_dir(k8s_conf)})

        if dpdk_enable is True:
            logger.info('INSTALLING SRIOV DPDK BIN ON MASTER')
            ansible_utils.apply_playbook(
                consts.K8_SRIOV_DPDK_CNI_BIN_INST, [ip], consts.NODE_USER,
                variables={
                    'SRC_PACKAGE_PATH':
                        config_utils.get_artifact_dir(k8s_conf)})

    minon_ips = config_utils.get_minion_node_ips(k8s_conf)
    ansible_utils.apply_playbook(
        consts.K8_SRIOV_DPDK_CNI_BIN_INST, [minon_ips], consts.NODE_USER,
        variables={
            'SRC_PACKAGE_PATH': config_utils.get_artifact_dir(k8s_conf)})

    if dpdk_enable is True:
        logger.info('INSTALLING SRIOV DPDK BIN ON WORKERS')
        ansible_utils.apply_playbook(
            consts.K8_SRIOV_DPDK_DRIVER_LOAD, [minon_ips], consts.NODE_USER,
            variables={'dpdk_driver': dpdk_driver})

        ansible_utils.apply_playbook(
            consts.K8_SRIOV_DPDK_CNI_BIN_INST, [minon_ips], consts.NODE_USER,
            variables={
                'SRC_PACKAGE_PATH': config_utils.get_artifact_dir(k8s_conf)})


def launch_sriov_network_creation(k8s_conf):
    sriov_cfgs = config_utils.get_multus_cni_sriov_cfgs(k8s_conf)
    for sriov_cfg in sriov_cfgs:
        for key, host in sriov_cfg.items():
            __launch_sriov_network(k8s_conf, host)


def __launch_sriov_network(k8s_conf, sriov_host):
    master_host, ip = config_utils.get_first_master_host(k8s_conf)

    for sriov_net in sriov_host[consts.SRIOV_NETWORKS_KEY]:
        dpdk_enable = config_utils.bool_val(sriov_net.get(
            consts.SRIOV_DPDK_ENABLE_KEY))

        if dpdk_enable:
            logger.info('SRIOV NETWORK CREATION STARTED USING DPDK DRIVER')

            host_type = sriov_net.get(consts.TYPE_KEY)
            sriov_intf = sriov_net.get(consts.SRIOV_INTF_KEY)
            sriov_nw_name = sriov_net.get(consts.NETWORK_NAME_KEY)
            pb_vars = {
                'intf': sriov_intf,
                'network_name': sriov_nw_name,
                'dpdk_driver': consts.DPDK_DRIVER,
                'dpdk_tool': consts.DPDK_TOOL,
                'node_hostname': sriov_host.get(consts.HOSTNAME_KEY),
                'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(
                    k8s_conf),
            }
            ansible_utils.apply_playbook(
                consts.K8_SRIOV_DPDK_CR_NW, [master_host],
                consts.NODE_USER, variables=pb_vars)

            if host_type == consts.NET_TYPE_LOCAL_TYPE:
                logger.info('SRIOV NETWORK CREATION STARTED USING '
                            'KERNEL DRIVER WITH IPAM host-local')

                pb_vars = {
                    'host_name': master_host,
                    'intf': sriov_intf,
                    'network_name': sriov_nw_name,
                    'rangeStart': sriov_net.get(consts.RANGE_START_KEY),
                    'rangeEnd': sriov_net.get(consts.RANGE_END_KEY),
                    'subnet': sriov_net.get(consts.SUBNET_KEY),
                    'gateway': sriov_net.get(consts.GATEWAY_KEY),
                    'masterPlugin': sriov_net.get(consts.MASTER_PLUGIN_KEY),
                    'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(
                        k8s_conf),
                }
                ansible_utils.apply_playbook(
                    consts.K8_SRIOV_CR_NW, [master_host], consts.NODE_USER,
                    variables=pb_vars)

            if host_type == consts.DHCP_TYPE:
                logger.info(
                    'SRIOV NETWORK CREATION STARTED USING '
                    'KERNEL DRIVER WITH IPAM host-dhcp')
                pb_vars = {
                    'intf': sriov_intf,
                    'network_name': sriov_nw_name,
                    'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(
                        k8s_conf),
                }
                pb_vars.update(config_utils.get_proxy_dict(k8s_conf))
                ansible_utils.apply_playbook(
                    consts.K8_SRIOV_DHCP_CR_NW, [master_host],
                    consts.NODE_USER, variables=pb_vars)


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
        'networking_plugin': networking_plugin,
        'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(k8s_conf),
    }
    pb_vars.update(config_utils.get_proxy_dict(k8s_conf))
    hostname, ip = config_utils.get_first_master_host(k8s_conf)
    ansible_utils.apply_playbook(
        consts.K8_CREATE_DEFAULT_NETWORK, [ip], consts.NODE_USER,
        variables=pb_vars)


def create_flannel_interface(k8s_conf):
    logger.info('EXECUTING FLANNEL INTERFACE CREATION PLAY IN CREATE FUNC')
    master_host, master_ip = config_utils.get_first_master_host(k8s_conf)

    flannel_cfgs = config_utils.get_multus_cni_flannel_cfgs(k8s_conf)
    for flannel_cfg in flannel_cfgs:
        for key, flannel_details in flannel_cfg.items():
            network = flannel_details.get(consts.NETWORK_KEY)
            cidr = flannel_details.get(consts.SUBNET_KEY)
            master_hosts_t3 = config_utils.get_master_nodes_ip_name_type(
                k8s_conf)
            for host_name, ip, node_type in master_hosts_t3:
                pb_vars = {
                    'network': network,
                    'cidr': cidr,
                }
                ansible_utils.apply_playbook(
                    consts.K8_CONF_FLANNEL_DAEMON_AT_MASTER, [ip],
                    consts.NODE_USER, variables=pb_vars)

                pb_vars = {
                    'SRC_PACKAGE_PATH':
                        config_utils.get_artifact_dir(k8s_conf),
                    'network': network,
                    'ip': ip,
                    'node_user': consts.NODE_USER,
                }
                ansible_utils.apply_playbook(
                    consts.K8_CONF_COPY_FLANNEL_CNI, variables=pb_vars)

            pb_vars = {
                'networkName': flannel_details.get(consts.NETWORK_NAME_KEY),
                'masterPlugin': flannel_details.get(consts.MASTER_PLUGIN_KEY),
                'SRC_PACKAGE_PATH': config_utils.get_artifact_dir(k8s_conf),
                'Project_name': config_utils.get_project_name(k8s_conf),
                'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(
                    k8s_conf),
            }
            pb_vars.update(config_utils.get_proxy_dict(k8s_conf))
            ansible_utils.apply_playbook(
                consts.K8_CONF_FLANNEL_INTF_CREATION_AT_MASTER,
                [master_ip], consts.NODE_USER, variables=pb_vars)


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
            'SRC_PACKAGE_PATH': config_utils.get_artifact_dir(k8s_conf),
        }
        ansible_utils.apply_playbook(
            consts.K8_CONF_COPY_WEAVE_CNI, [ip], consts.NODE_USER,
            variables=pb_vars)

    master_host, master_ip = config_utils.get_first_master_host(k8s_conf)
    logger.info('CREATING WEAVE NETWORKS on %s|%s', master_host, master_ip)
    pb_vars = {
        'networkName': network_name,
        'subnet': subnet,
        'masterPlugin': master_plugin,
        'SRC_PACKAGE_PATH': config_utils.get_artifact_dir(k8s_conf),
        'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(k8s_conf),
    }
    pb_vars.update(config_utils.get_proxy_dict(k8s_conf))
    ansible_utils.apply_playbook(
        consts.K8_CONF_WEAVE_NETWORK_CREATION, [master_ip], consts.NODE_USER,
        variables=pb_vars)

    ips = config_utils.get_minion_node_ips(k8s_conf)
    networking_plugin = config_utils.get_networking_plugin(k8s_conf)
    ansible_utils.apply_playbook(
        consts.K8_CONF_FILES_DELETION_AFTER_MULTUS, ips, consts.NODE_USER,
        variables={
            'networking_plugin': networking_plugin,
            'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(
                k8s_conf),
            'Project_name': config_utils.get_project_name(k8s_conf),
        })


def clean_up_metrics_server(k8s_conf):
    logger.info("clean_up_metrics_server")
    if config_utils.is_metrics_server_enabled(k8s_conf):
        masters_t3 = config_utils.get_master_nodes_ip_name_type(k8s_conf)
        pb_vars = {
            'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(
                k8s_conf),
        }
        pb_vars.update(config_utils.get_proxy_dict(k8s_conf))

        for host_name, ip, node_type in masters_t3:
            ansible_utils.apply_playbook(
                consts.K8_METRICS_SERVER_CLEAN, [host_name], consts.NODE_USER,
                variables=pb_vars)
            break


def launch_ceph_kubernetes(k8s_conf):
    """
    This function is used for deploy the ceph
    """

    ceph_hosts = config_utils.get_ceph_hosts(k8s_conf)
    ceph_mon_list= config_utils.get_ceph_ctrls(k8s_conf)
    proxy_dict = config_utils.get_proxy_dict(k8s_conf)
    if ceph_hosts:
        pb_vars = {
            'ceph_hosts' : ceph_hosts
                  }
        ansible_utils.apply_playbook(consts.KUBERNETES_CEPH_ADD_HOSTS, variables=pb_vars)
        pb_vars = {
            'ceph_hosts' : ceph_hosts,
            'project_name': config_utils.get_project_name(k8s_conf),
            'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(k8s_conf),
                  }

        pb_vars.update(config_utils.get_proxy_dict(k8s_conf))
        ansible_utils.apply_playbook(consts.KUBERNETES_CEPH_INSTALL, variables=pb_vars)


    for ceph_mon in ceph_mon_list:
        claims = ceph_mon[consts.CEPH_CLAIMS_KEY]
        if claims:
            pb_vars = {
                'ceph_hosts' : ceph_hosts,
                'SRC_PACKAGE_PATH': config_utils.get_artifact_dir(
                        k8s_conf),
                'KUBERNETES_PATH': consts.NODE_K8S_PATH,
                'project_name': config_utils.get_project_name(k8s_conf),
                'ceph_claims': claims,
                'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(k8s_conf),
                      }

            pb_vars.update(config_utils.get_proxy_dict(k8s_conf))
            ansible_utils.apply_playbook(consts.KUBERNETES_CEPH_PVC, variables=pb_vars)



def launch_persitent_volume_kubernetes(k8s_conf):
    """
    This function is used for deploy the persistent_volume
    """

    vol_claims = config_utils.get_persist_vol_claims(k8s_conf)
    ceph_hosts = config_utils.get_ceph_hosts(k8s_conf)
    if vol_claims:
        pb_vars = {
            'ceph_hosts' : ceph_hosts,
            'SRC_PACKAGE_PATH': config_utils.get_artifact_dir(
                    k8s_conf),
            'KUBERNETES_PATH': consts.NODE_K8S_PATH,
            'project_name': config_utils.get_project_name(k8s_conf),
            'persistent_vol': vol_claims,
            'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(k8s_conf),
                      }

        pb_vars.update(config_utils.get_proxy_dict(k8s_conf))
        ansible_utils.apply_playbook(consts.KUBERNETES_PERSISTENT_VOLUME, variables=pb_vars)



def __enable_cluster_logging(k8s_conf):
    """
    This function is used to enable logging in cluster
    :param k8s_conf: k8s config
    """
    if config_utils.is_logging_enabled(k8s_conf):
        log_level = config_utils.get_log_level(k8s_conf)
        if (log_level != "fatal" and log_level != "warning"
                and log_level != "info" and log_level != "debug"
                and log_level != "critical"):
            raise Exception('Invalid log_level')

        pb_vars = {
            "logging": 'True',
            "log_level": log_level,
            "file_path": consts.LOG_FILE_PATH,
            "logging_port": config_utils.get_logging_port(k8s_conf),
            'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(
                k8s_conf),
            'KUBESPRAY_PATH': config_utils.get_kubespray_dir(k8s_conf)
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
    lb_ips = config_utils.get_ha_lb_ips(k8s_conf)
    if len(lb_ips) > 0:
        lb_ip = lb_ips[0]

    logger.info("Load balancer ip %s", lb_ip)

    host_name, ip = config_utils.get_first_master_host(k8s_conf)
    ha_enabled = len(lb_ips) > 0
    if ha_enabled:
        pb_vars = {
            'SRC_PACKAGE_PATH': config_utils.get_artifact_dir(k8s_conf),
            'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(
                k8s_conf),
            'Project_name': config_utils.get_project_name(k8s_conf),
        }
        pb_vars.update(config_utils.get_proxy_dict(k8s_conf))
    pb_vars = {
        'ip': ip,
        'host_name': host_name,
        'ha_enabled': ha_enabled,
        'Project_name': config_utils.get_project_name(k8s_conf),
        'lb_ip': lb_ip,
        'SRC_PACKAGE_PATH': config_utils.get_artifact_dir(
            k8s_conf),
        'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(
            k8s_conf),
    }
    pb_vars.update(config_utils.get_proxy_dict(k8s_conf))
    ansible_utils.apply_playbook(consts.K8_KUBECTL_INSTALLATION,
                                 variables=pb_vars)


def __config_master(k8s_conf, base_pb_vars):
    master_nodes_t3 = config_utils.get_master_nodes_ip_name_type(k8s_conf)
    for host_name, ip, node_type in master_nodes_t3:
        pb_vars = {
            'SRC_PACKAGE_PATH': config_utils.get_artifact_dir(
                k8s_conf),
            'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(
                k8s_conf),
        }
        if node_type == "master":
            ansible_utils.apply_playbook(consts.KUBERNETES_WEAVE_SCOPE,
                                         variables=pb_vars)
            pb_vars = {
                'host_name': host_name,
            }
            pb_vars.update(base_pb_vars)
            ansible_utils.apply_playbook(
                consts.KUBERNETES_KUBE_PROXY, [host_name], consts.NODE_USER,
                variables=pb_vars)
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
            'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(
                k8s_conf),
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
        'SRC_PACKAGE_PATH': config_utils.get_artifact_dir(
            k8s_conf),
        'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(
            k8s_conf),
    }
    ansible_utils.apply_playbook(consts.K8_DELETE_WEAVE_INTERFACE,
                                 variables=pb_vars)

    ips = config_utils.get_minion_node_ips(k8s_conf)
    for ip in ips:
        pb_vars = {
            'ip': ip,
            'node_type': consts.NODE_TYPE_MINION,
            'networkName': network_name,
            'SRC_PACKAGE_PATH': config_utils.get_artifact_dir(
                k8s_conf),
            'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(
                k8s_conf),
        }
        ansible_utils.apply_playbook(consts.K8_DELETE_WEAVE_INTERFACE,
                                     variables=pb_vars)


def delete_flannel_interfaces(k8s_conf):
    """
    This function is used to delete flannel interfaces
    """
    logger.info('EXECUTING FLANNEL INTERFACE DELETION PLAY')
    multus_flannel_cfgs = config_utils.get_multus_cni_flannel_cfgs(k8s_conf)

    for multus_flannel_cfg in multus_flannel_cfgs:
        hostdetails = multus_flannel_cfg.get(consts.FLANNEL_NET_DTLS_KEY)
        network_name = hostdetails.get(consts.NETWORK_NAME_KEY)

        pb_vars = {
            'node_type': consts.NODE_TYPE_MASTER,
            'networkName': network_name,
            'SRC_PACKAGE_PATH': config_utils.get_artifact_dir(
                k8s_conf),
            'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(
                k8s_conf),
        }
        master_host_name, master_ip = config_utils.get_first_master_host(
            k8s_conf)
        if master_ip:
            ansible_utils.apply_playbook(
                consts.K8_DELETE_FLANNEL_INTERFACE, [master_ip],
                consts.NODE_USER, variables=pb_vars)


def delete_weave_interface(k8s_conf):
    """
    This function is used to delete weave interface
    """
    logger.info('EXECUTING WEAVE INTERFACE DELETION PLAY')
    master_host_name, master_ip = config_utils.get_first_master_host(k8s_conf)
    logger.info('DELETING WEAVE INTERFACE.. Master ip: %s, Master Host '
                'Name: %s', master_ip, master_host_name)

    weave_details = config_utils.get_multus_cni_weave_cfgs(k8s_conf)
    for weave_detail in weave_details:
        network_name = weave_detail.get(consts.NETWORK_NAME_KEY)
        pb_vars = {
            'node_type': consts.NODE_TYPE_MASTER,
            'networkName': network_name,
            'SRC_PACKAGE_PATH': config_utils.get_artifact_dir(
                k8s_conf),
            'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(
                k8s_conf),
            'Project_name': config_utils.get_project_name(k8s_conf),
        }
        ansible_utils.apply_playbook(consts.K8_DELETE_WEAVE_INTERFACE,
                                     variables=pb_vars)


def __ha_configuration(k8s_conf):
    """HA configuration """
    if config_utils.get_ha_config(k8s_conf):
        logger.info('HA CONFIGURING')
        __launch_ha_loadbalancer_conf(k8s_conf)
        __launch_kubespray_ha_configure(k8s_conf)


def __launch_ha_loadbalancer_conf(k8s_conf):
    """
    function used to call launch_load_balancer
    :param k8s_conf: the config dict object
    :return:
    """
    loadbalancer_dict = config_utils.get_loadbalancer_dict(k8s_conf)
    lb_port = loadbalancer_dict.get("port")
    master_ip_list = config_utils.get_master_node_ips(k8s_conf)
    pb_vars = {
        'MASTER_IP_LIST': str(master_ip_list),
        'lb_port': lb_port,
    }
    pb_vars.update(config_utils.get_proxy_dict(k8s_conf))
    ansible_utils.apply_playbook(
        consts.K8_HA_EXT_LB, [loadbalancer_dict.get(consts.IP_KEY)],
        consts.NODE_USER, variables=pb_vars)


def __launch_kubespray_ha_configure(k8s_conf):
    """
    fucntion used to call kubespray_ha_configure
    :param k8s_conf: the config dict object
    """
    loadbalancer_dict = config_utils.get_loadbalancer_dict(k8s_conf)
    pb_vars = {
        'LOADBALANCER_IP': loadbalancer_dict.get(consts.IP_KEY),
        'PROJ_ARTIFACT_DIR': config_utils.get_project_artifact_dir(k8s_conf),
    }
    pb_vars.update(config_utils.get_proxy_dict(k8s_conf))
    ansible_utils.apply_playbook(consts.K8_HA_KUBESPRAY_CONFIGURE,
                                 variables=pb_vars)

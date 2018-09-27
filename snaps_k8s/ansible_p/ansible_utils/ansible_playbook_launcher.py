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

import subprocess
import logging

import os

__author__ = '_ARICENT'

logger = logging.getLogger('ansible_playbook_operations')
ANSIBLE_EXE = 'ansible-playbook'


def create_extra_var_str(vars_dict):
    """
    This method encodes variables into an --extra-vars string
    :param vars_dict:
    :return: a string that can be added to the ansible-playbook exe
    """
    if len(vars_dict) < 1:
        return ''

    out_val = "--extra-vars='{"
    for key, value in vars_dict.items():
        out_val = '{}"{}":"{}",'.format(out_val, key, value)

    out_val = "{}{}".format(out_val[:-1], "}'")
    return out_val


def execute_system_command(playbook, extra_var_str):
    """
    Executes a playbook through os.system function
    :playbook: Playbook to be executed
    :extra_vars: extra variables to be passed to playbook
    :return: True/False - True if successful
    """
    command = "{} {} {} {}".format(
        ANSIBLE_EXE,
        "--ssh-extra-args='-o StrictHostKeyChecking=no'",
        playbook, extra_var_str)

    logger.info(command)
    retval = os.system(command)
    return retval == 0


def execute_system_cmd_subprocess(playbook, extra_var_str):
    """
    Executes a playbook through os.system function
    :playbook: Playbook to be executed
    :extra_vars: extra variables to be passed to playbook
    :return: True/False - True if successful
    """
    command = "{} {} {}".format(ANSIBLE_EXE, playbook, extra_var_str)
    logger.info(command)

    try:
        returned_output = subprocess.check_output(command, shell=True)
        logger.info(returned_output)
    except subprocess.CalledProcessError as exception:
        logger.info(exception)
        logger.error('Failed Execution for playbook %s', playbook)
        return False
    return True


def kubespray_play(playbook, proxy_data_file, var_file, src_pkg_path,
                   git_branch, project_name):
    """
    Applies ansible playbooks to clone the kubspray code
    :param playbook:
    :param proxy_data_file:
    :param var_file:
    :param src_pkg_path:
    :param git_branch:
    :param project_name:
    :return:
    """
    extra_var_str = create_extra_var_str({
        'PROXY_DATA_FILE': proxy_data_file,
        'VARIABLE_FILE': var_file,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'Git_branch': git_branch,
        'Project_name': project_name,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def clone_packages(playbook, proxy_data_file, var_file, src_pkg_path,
                   git_branch):
    """
    Applies ansible playbooks to clone the packages
    :param playbook:
    :param proxy_data_file:
    :param var_file:
    :param src_pkg_path:
    :param git_branch:
    :return:
    """
    extra_var_str = create_extra_var_str({
        'PROXY_DATA_FILE': proxy_data_file,
        'VARIABLE_FILE': var_file,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'Git_branch': git_branch,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def enable_loggings(playbook, proxy_data_file, var_file, log_val, project_name,
                    log_level, file_path, logging_port):
    """
    Applies ansible playbooks to enable logging
    :param playbook:
    :param proxy_data_file:
    :param var_file:
    :param log_val:
    :param project_name:
    :param log_level:
    :param file_path:
    :param logging_port:
    :return:
    """
    extra_var_str = create_extra_var_str({
        'PROXY_DATA_FILE': proxy_data_file,
        'VARIABLE_FILE': var_file,
        "logging": log_val,
        'Project_name': project_name,
        "log_level": log_level,
        "file_path": file_path,
        "logging_port": logging_port,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def cpu_manager_configuration(playbook, proxy_data_file, var_file):
    """
    Configure CPU management policies in Cluster
    """
    extra_var_str = create_extra_var_str({
        'PROXY_DATA_FILE': proxy_data_file,
        'VARIABLE_FILE': var_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_cmd_subprocess(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def launch_k8s(playbook, service_subnet, pod_subnet, networking_plugin,
               proxy_data_file, var_file, src_pkg_path, cwd, git_branch,
               project_name, kube_version):
    """
    Applies ansible playbooks to the listed hosts with provided IPs
    :return: t/f - true if successful
    """
    extra_var_str = create_extra_var_str({
        'service_subnet': service_subnet,
        'pod_subnet': pod_subnet,
        'networking_plugin': networking_plugin,
        'kube_version': kube_version,
        'PROXY_DATA_FILE': proxy_data_file,
        'VARIABLE_FILE': var_file,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'Git_branch': git_branch,
        'Project_name': project_name,
        'CURRENT_DIR': cwd,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def launch_inventory(playbook, node_type, host_name, src_pkg_path, var_file,
                     proj_name):
    extra_var_str = create_extra_var_str({
        'node_type': node_type,
        'host_name': host_name,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'VARIABLE_FILE': var_file,
        'Project_name': proj_name,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def launch_new_inventory(playbook, ip, host_name, src_pkg_path, var_file, cwd,
                         proj_name):
    extra_var_str = create_extra_var_str({
        'ip': ip,
        'host_name': host_name,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'VARIABLE_FILE': var_file,
        'CURRENT_DIR': cwd,
        'Project_name': proj_name,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def update_user_list(playbook, user_name, user_password, user_id,
                     src_pkg_path):
    extra_var_str = create_extra_var_str({
        'user_name': user_name,
        'user_password': user_password,
        'user_id': user_id,
        'SRC_PACKAGE_PATH': src_pkg_path,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def launch_authentication(playbook, host_name, src_pkg_path, var_file):
    extra_var_str = create_extra_var_str({
        'host_name': host_name,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'VARIABLE_FILE': var_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def etcd_changes(playbook, host_name, ip, src_pkg_path, var_file):
    extra_var_str = create_extra_var_str({
        'host_name': host_name,
        'ip': ip,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'VARIABLE_FILE': var_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def ceph_storage(playbook, host_name, master_host_name, src_pkg_path,
                 var_file, storage, proxy_data_file, node_type):
    extra_var_str = create_extra_var_str({
        'host_name': host_name,
        'master_host_name': master_host_name,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'VARIABLE_FILE': var_file,
        'PROXY_DATA_FILE': proxy_data_file,
        'storage': storage,
        'node_type': node_type,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def ceph_volume2(playbook, host_name, src_pkg_path, var_file,
                 ceph_storage_size, ceph_claim_name, proxy_data_file,
                 controller_host_name, ceph_controller_ip):
    extra_var_str = create_extra_var_str({
        'host_name': host_name,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'VARIABLE_FILE': var_file,
        'ceph_storage_size': ceph_storage_size,
        'ceph_claim_name': ceph_claim_name,
        'PROXY_DATA_FILE': proxy_data_file,
        'controller_host_name': controller_host_name,
        'ceph_controller_ip': ceph_controller_ip,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def ceph_volume_first(playbook, host_name, src_pkg_path, var_file,
                      proxy_data_file, host_ip):
    extra_var_str = create_extra_var_str({
        'host_name': host_name,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'VARIABLE_FILE': var_file,
        'PROXY_DATA_FILE': proxy_data_file,
        'host_ip': host_ip,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def ceph_mon(playbook, master_host_name, var_file, proxy_data_file):
    extra_var_str = create_extra_var_str({
        'master_host_name': master_host_name,
        'VARIABLE_FILE': var_file,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def ceph_deploy(playbook, host_name, master_host_name, var_file,
                proxy_data_file, user_id, passwd):
    extra_var_str = create_extra_var_str({
        'host_name': host_name,
        'master_host_name': master_host_name,
        'VARIABLE_FILE': var_file,
        'PROXY_DATA_FILE': proxy_data_file,
        'user_id': user_id,
        'passwd': passwd,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def ceph_deploy_admin(playbook, host_name, master_host_name, var_file,
                      proxy_data_file):
    extra_var_str = create_extra_var_str({
        'host_name': host_name,
        'master_host_name': master_host_name,
        'VARIABLE_FILE': var_file,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def ceph_volume(playbook, host_name, src_pkg_path, var_file, proxy_data_file,
                osd_host_name, user_id, passwd, osd_ip):
    extra_var_str = create_extra_var_str({
        'host_name': host_name,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'VARIABLE_FILE': var_file,
        'PROXY_DATA_FILE': proxy_data_file,
        'osd_host_name': osd_host_name,
        'user_id': user_id,
        'passwd': passwd,
        'osd_ip': osd_ip,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def node_labeling(playbook, master_hostname, hostname, label_key, label_value,
                  proxy_data_file):
    extra_var_str = create_extra_var_str({
        'master_hostname': master_hostname,
        'hostname': hostname,
        'label_key': label_key,
        'label_value': label_value,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def delete_secret(playbook, master_hostname, proxy_data_file):
    extra_var_str = create_extra_var_str({
        'master_hostname': master_hostname,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def persistent_volume(playbook, host_name, src_pkg_path, var_file,
                      storage_size, claim_name, proxy_data_file):
    extra_var_str = create_extra_var_str({
        'host_name': host_name,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'VARIABLE_FILE': var_file,
        'storage_size': storage_size,
        'claim_name': claim_name,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def weave_scope(playbook, host_name, src_pkg_path, var_file, proxy_data_file):
    extra_var_str = create_extra_var_str({
        'host_name': host_name,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'VARIABLE_FILE': var_file,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def delete_node(playbook, host_name, src_pkg_path, var_file, project_name):
    extra_var_str = create_extra_var_str({
        'host_name': host_name,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'VARIABLE_FILE': var_file,
        'Project_name': project_name,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def kube_proxy(playbook, host_name, src_pkg_path, var_file, proxy_data_file):
    extra_var_str = create_extra_var_str({
        'host_name': host_name,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'VARIABLE_FILE': var_file,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def delete_host_k8(playbook, ip, host_name, host_file_path,
                   ansible_host_file_path, var_file, project_name,
                   multus_enabled):
    extra_var_str = create_extra_var_str({
        'ip': ip,
        'host_name': host_name,
        'HOST_FILE_PATH': host_file_path,
        'ANSIBLE_HOST_FILE_PATH': ansible_host_file_path,
        'VARIABLE_FILE': var_file,
        'Project_name': project_name,
        'multus_enabled': multus_enabled,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def delete_project_folder(playbook, var_file, src_pkg_path, project_name,
                          proxy_data_file):
    extra_var_str = create_extra_var_str({
        'SRC_PACKAGE_PATH': src_pkg_path,
        'VARIABLE_FILE': var_file,
        'Project_name': project_name,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def clean_k8(playbook, src_pkg_path, var_file, proxy_data_file, git_branch,
             project_name):
    extra_var_str = create_extra_var_str({
        'SRC_PACKAGE_PATH': src_pkg_path,
        'VARIABLE_FILE': var_file,
        'PROXY_DATA_FILE': proxy_data_file,
        'Git_branch': git_branch,
        'Project_name': project_name,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def set_k8s_packages(playbook, target, host_name, proxy_data_file, var_file,
                     apt_arch_src, src_pkg_path, registry_port):
    extra_var_str = create_extra_var_str({
        'target': target,
        'host_name': host_name,
        'PROXY_DATA_FILE': proxy_data_file,
        'VARIABLE_FILE': var_file,
        'APT_ARCHIVES_SRC': apt_arch_src,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'registry_port': registry_port,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def creating_docker_repo(playbook, proxy_data_file, var_file, docker_ip,
                         docker_port, apt_arch_src, src_pkg_path):
    extra_var_str = create_extra_var_str({
        'PROXY_DATA_FILE': proxy_data_file,
        'VARIABLE_FILE': var_file,
        'docker_ip': docker_ip,
        'docker_port': docker_port,
        'APT_ARCHIVES_SRC': apt_arch_src,
        'SRC_PACKAGE_PATH': src_pkg_path,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def create_inventory_file(playbook, src_pkg_path, var_file, cwd, project_name):
    extra_var_str = create_extra_var_str({
        'SRC_PACKAGE_PATH': src_pkg_path,
        'VARIABLE_FILE': var_file,
        'CURRENT_DIR': cwd,
        'Project_name': project_name,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def docker_conf(playbook, target, host_name, proxy_data_file, var_file,
                docker_ip, docker_port):
    extra_var_str = create_extra_var_str({
        'target': target,
        'host_name': host_name,
        'PROXY_DATA_FILE': proxy_data_file,
        'VARIABLE_FILE': var_file,
        'docker_ip': docker_ip,
        'docker_port': docker_port,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def create_crd_network(playbook, ip, host_name, src_pkg_path, proxy_data_file):
    extra_var_str = create_extra_var_str({
        'ip': ip,
        'host_name': host_name,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def master_multus(playbook, ip, host_name, networking_plugin, src_pkg_path,
                  proxy_data_file):
    extra_var_str = create_extra_var_str({
        'ip': ip,
        'host_name': host_name,
        'networking_plugin': networking_plugin,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def copy_multus(playbook, ip, host_name, networking_plugin, src_pkg_path):
    extra_var_str = create_extra_var_str({
        'ip': ip,
        'host_name': host_name,
        'networking_plugin': networking_plugin,
        'SRC_PACKAGE_PATH': src_pkg_path,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def node_multus(playbook, ip, host_name, networking_plugin, src_pkg_path):
    extra_var_str = create_extra_var_str({
        'ip': ip,
        'host_name': host_name,
        'networking_plugin': networking_plugin,
        'SRC_PACKAGE_PATH': src_pkg_path,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def master_flannel(playbook, ip, host_name, networking_plugin, network,
                   subnet_len, vni, src_pkg_path):
    extra_var_str = create_extra_var_str({
        'ip': ip,
        'host_name': host_name,
        'networking_plugin': networking_plugin,
        'network': network,
        'subnetLen': subnet_len,
        'vni': vni,
        'SRC_PACKAGE_PATH': src_pkg_path,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def node_flannel(playbook, ip, host_name, networking_plugin, network,
                 subnet_len, vni, master_ip, src_pkg_path):
    extra_var_str = create_extra_var_str({
        'ip': ip,
        'host_name': host_name,
        'networking_plugin': networking_plugin,
        'network': network,
        'subnetLen': subnet_len,
        'vni': vni,
        'master_ip': master_ip,
        'SRC_PACKAGE_PATH': src_pkg_path,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def create_flannel_networks(playbook, ip, host_name, net_name, vni, vni_temp,
                            src_pkg_path, proxy_data_file):
    extra_var_str = create_extra_var_str({
        'ip': ip,
        'host_name': host_name,
        'networkName': net_name,
        'vni': vni,
        'vniTemp': vni_temp,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def enable_sriov(playbook, host_name, intf, script, networking_plugin):
    extra_var_str = create_extra_var_str({
        'host_name': host_name,
        'sriov_intf': intf,
        'script_path': script,
        'networking_plugin': networking_plugin,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def build_sriov(playbook, src_pkg_path, proxy_data_file):
    extra_var_str = create_extra_var_str({
        'SRC_PACKAGE_PATH': src_pkg_path,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def build_sriov_dpdk(playbook, src_pkg_path, proxy_data_file):
    extra_var_str = create_extra_var_str({
        'SRC_PACKAGE_PATH': src_pkg_path,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def sriov_install(playbook, host_name, src_pkg_path):
    extra_var_str = create_extra_var_str({
        'host_name': host_name,
        'SRC_PACKAGE_PATH': src_pkg_path,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def sriov_dpdk_install(playbook, host_name, src_pkg_path):
    extra_var_str = create_extra_var_str({
        'host_name': host_name,
        'SRC_PACKAGE_PATH': src_pkg_path,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def dpdk_driver_load(playbook, host_name, dpdk_driver):
    extra_var_str = create_extra_var_str({
        'host_name': host_name,
        'dpdk_driver': dpdk_driver,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def sriov_dpdk_crd_nw(playbook, sriov_intf,
                      host_name, nw_name, dpdk_driver, dpdk_tool,
                      node_hostname, master_plugin, proxy_data_file):
    extra_var_str = create_extra_var_str({
        'host_name': host_name,
        'intf': sriov_intf,
        'network_name': nw_name,
        'dpdk_driver': dpdk_driver,
        'dpdk_tool': dpdk_tool,
        'node_hostname': node_hostname,
        'masterPlugin': master_plugin,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def sriov_dhcp_crd_nw(playbook, sriov_intf,
                      host_name, nw_name, proxy_data_file):
    extra_var_str = create_extra_var_str({
        'host_name': host_name,
        'intf': sriov_intf,
        'PROXY_DATA_FILE': proxy_data_file,
        'network_name': nw_name,
    })
    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def sriov_crd_nw(playbook, sriov_intf, host_name,
                 nw_name, s_rng, e_rng, subnet, gw, master_plugin,
                 proxy_data_file):
    extra_var_str = create_extra_var_str({
        'host_name': host_name,
        'intf': sriov_intf,
        'network_name': nw_name,
        'rangeStart': s_rng,
        'rangeEnd': e_rng,
        'subnet': subnet,
        'gateway': gw,
        'masterPlugin': master_plugin,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def vlantag_interface(playbook, host, parent_intf, vlan_id, ip):
    extra_var_str = create_extra_var_str({
        'host': host,
        'parentInterface': parent_intf,
        'vlanId': str(vlan_id),
        'ip': ip,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def vlantag_interface_removal(playbook, host, parent_intf, vlan_id):
    extra_var_str = create_extra_var_str({
        'host': host,
        'parentInterface': parent_intf,
        'vlanId': str(vlan_id),
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def network_creation(playbook, host, network_name, interface_node, subnet,
                     range_start, range_end, dst, gateway, proxy_data_file):
    extra_var_str = create_extra_var_str({
        'host': host,
        'network_name': network_name,
        'interface_node': interface_node,
        'subnet': subnet,
        'rangeStart': range_start,
        'rangeEnd': range_end,
        'dst': dst,
        'gateway': gateway,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def network_removal(playbook, host, network_name, proxy_data_file):
    extra_var_str = create_extra_var_str({
        'host': host,
        'network_name': network_name,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def network_dhcp_creation(playbook, host, network_name, interface_node,
                          proxy_data_file):
    extra_var_str = create_extra_var_str({
        'host': host,
        'network_name': network_name,
        'interface_node': interface_node,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def dhcp_daemon_creation(playbook, host):
    extra_var_str = create_extra_var_str({
        'host': host,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def dhcp_daemon_removal(playbook, host):
    extra_var_str = create_extra_var_str({
        'host': host,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def clean_docker(playbook, host_name):
    extra_var_str = create_extra_var_str({'host_name': host_name})

    logger.info("Arguments are %s", str(extra_var_str))
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def create_weave_network(playbook, ip, host_name, network_name, subnet,
                         master_plugin, src_pkg_path, proxy_data_file):
    extra_var_str = create_extra_var_str({
        'ip': ip,
        'host_name': host_name,
        'networkName': network_name,
        'subnet': subnet,
        'masterPlugin': master_plugin,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def delete_weave_conf(playbook, ip, host_name, networking_plugin,
                      src_pkg_path):
    extra_var_str = create_extra_var_str({
        'ip': ip,
        'host_name': host_name,
        'networking_plugin': networking_plugin,
        'SRC_PACKAGE_PATH': src_pkg_path,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def copy_weave_cni(playbook, ip, host_name, subnet, src_pkg_path):
    extra_var_str = create_extra_var_str({
        'ip': ip,
        'host_name': host_name,
        'subnet': subnet,
        'SRC_PACKAGE_PATH': src_pkg_path,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def delete_conf_files(playbook, ip, host_name, networking_plugin,
                      src_pkg_path):
    extra_var_str = create_extra_var_str({
        'ip': ip,
        'host_name': host_name,
        'networking_plugin': networking_plugin,
        'SRC_PACKAGE_PATH': src_pkg_path,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def metrics_server(playbook, ip, host_name, proxy_data_file):
    """
    fucntion added for metrics server
    """
    extra_var_str = create_extra_var_str({
        'ip': ip,
        'host_name': host_name,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def metrics_server_clean(playbook, ip, host_name, proxy_data_file):
    """
    fucntion added by yashwant for metrics server remove
    """
    extra_var_str = create_extra_var_str({
        'ip': ip,
        'host_name': host_name,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def create_default_network(playbook, ip, host_name, network_name, subnet,
                           networking_plugin, master_plugin, src_pkg_path,
                           proxy_data_file):
    extra_var_str = create_extra_var_str({
        'ip': ip,
        'host_name': host_name,
        'networkName': network_name,
        'subnet': subnet,
        'networking_plugin': networking_plugin,
        'masterPlugin': master_plugin,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def flannel_daemon(playbook, ip, network, cidr, master_plugin, src_pkg_path):
    extra_var_str = create_extra_var_str({
        'ip': ip,
        'network': network,
        'cidr': str(cidr),
        'masterPlugin': master_plugin,
        'SRC_PACKAGE_PATH': src_pkg_path,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def create_flannel_interface(playbook, ip, host_name, network_name, network,
                             master_plugin, src_pkg_path, proxy_data_file):
    extra_var_str = create_extra_var_str({
        'ip': ip,
        'host_name': host_name,
        'networkName': network_name,
        'network': network,
        'masterPlugin': master_plugin,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def copy_flannel_cni(playbook, ip, host_name, network, src_pkg_path):
    extra_var_str = create_extra_var_str({
        'ip': ip,
        'host_name': host_name,
        'network': network,
        'SRC_PACKAGE_PATH': src_pkg_path,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def clean_sriov_rc_local(playbook, host_name, sriov_intf):
    extra_var_str = create_extra_var_str({
        'host_name': host_name,
        'sriov_intf': sriov_intf,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def weave_reclaim_ip(playbook, ip, host_name, node_hostname,
                     src_pkg_path):
    extra_var_str = create_extra_var_str({
        'ip': ip,
        'host_name': host_name,
        'node_hostname': node_hostname,
        'SRC_PACKAGE_PATH': src_pkg_path,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def weave_forget_ip(playbook, ip, host_name, node_hostname1, src_pkg_path):
    extra_var_str = create_extra_var_str({
        'ip': ip,
        'host_name': host_name,
        'node_hostname1': node_hostname1,
        'SRC_PACKAGE_PATH': src_pkg_path,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def install_dhcp_daemon(playbook, host):
    extra_var_str = create_extra_var_str({
        'host': host,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def dhcp_cleanup_network(playbook, host):
    extra_var_str = create_extra_var_str({
        'host': host,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def remove_sriov_networks(playbook, host, network_name):
    extra_var_str = create_extra_var_str({
        'host': host,
        'networkName': network_name,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def launch_install_kubectl(playbook, ip, host_name, ha_enabled,
                           project_name, lb_ip, var_file, src_pkg_path,
                           proxy_data_file):
    """
    function added for installing kubectl
    :param playbook:
    :param ip:
    :param host_name:
    :param ha_enabled:
    :param project_name:
    :param lb_ip:
    :param var_file:
    :param src_pkg_path:
    :param proxy_data_file:
    :return:
    """
    extra_var_str = create_extra_var_str({
        'ip': ip,
        'host_name': host_name,
        'ha_enabled': ha_enabled,
        'Project_name': project_name,
        'lb_ip': lb_ip,
        'VARIABLE_FILE': var_file,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def launch_set_kubectl_context(playbook, project_name, var_file, src_pkg_path,
                               proxy_data_file):
    """
    function added to set kubectl context
    :param playbook:
    :param project_name:
    :param var_file:
    :param src_pkg_path:
    :param proxy_data_file:
    :return:
    """
    extra_var_str = create_extra_var_str({
        'Project_name': project_name,
        'VARIABLE_FILE': var_file,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_command(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def launch_delete_flannel_interfaces(playbook, ip, host_name,
                                     node_type,
                                     network_name, src_pkg_path,
                                     proxy_data_file):
    extra_var_str = create_extra_var_str({
        'ip': ip,
        'host_name': host_name,
        'node_type': node_type,
        'networkName': network_name,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_cmd_subprocess(playbook, extra_var_str)
    logger.info('Exit')
    return retval


def launch_delete_weave_interface(playbook, ip, host_name, node_type,
                                  network_name, src_pkg_path,
                                  proxy_data_file):
    extra_var_str = create_extra_var_str({
        'ip': ip,
        'host_name': host_name,
        'node_type': node_type,
        'networkName': network_name,
        'SRC_PACKAGE_PATH': src_pkg_path,
        'PROXY_DATA_FILE': proxy_data_file,
    })

    logger.info("Arguments are %s", extra_var_str)
    retval = execute_system_cmd_subprocess(playbook, extra_var_str)
    logger.info('Exit')
    return retval

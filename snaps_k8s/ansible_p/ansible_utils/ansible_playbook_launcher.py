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


import subprocess
import logging
import os

__author__ = '_ARICENT'

logger = logging.getLogger('ansible_playbook_operations')

def execute_system_command(playbook, extra_vars):
    """
    Executes a playbook through os.system function
    :playbook: Playbook to be executed
    :extra_vars: extra variables to be passed to playbook
    :return: True/False - True if successful
    """
    command = '/usr/bin/ansible-playbook '+ playbook + ' --extra-vars=\'' + str(extra_vars).replace("'", '"')  + '\''
    logger.info(command)
    retval = os.system(command)
    return retval == 0

def execute_system_command_with_subprocess(playbook, extra_vars):
    """
    Executes a playbook through os.system function
    :playbook: Playbook to be executed
    :extra_vars: extra variables to be passed to playbook
    :return: True/False - True if successful
    """
    command = '/usr/bin/ansible-playbook '+ playbook + ' --extra-vars=\'' + str(extra_vars).replace("'", '"') + '\''
    logger.info(command)
    try:
        returned_output = subprocess.check_output(command, shell=True)
        logger.info(returned_output)
    except subprocess.CalledProcessError as exception:
        logger.info(exception)
        logger.error('Failed Execution for playbook %s', str(playbook))
        return False
    return True

def launch_clone_kubespray_play(playbook, PROXY_DATA_FILE, VARIABLE_FILE,
                                SRC_PACKAGE_PATH, Git_branch, Project_name):
    """
    Applies ansible playbooks to clone the kubspray code
    :param ansible_configs: a list of Ansible host configurations
    :param playbook_path: the path of the playbook  file
    :return: t/f - true if successful
    """
    extra_vars = {"PROXY_DATA_FILE": PROXY_DATA_FILE,
                  "VARIABLE_FILE": VARIABLE_FILE,
                  "SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "Git_branch": Git_branch,
                  "Project_name": Project_name}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_enable_logging(playbook, PROXY_DATA_FILE,
                                           VARIABLE_FILE, logging,
                                           Project_name, log_level,
                                           file_path, logging_port):
    """
    Applies ansible playbooks to enable logging
    :param playbook: the path of the playbook  file
    :param VARIABLE_FILE: Path of variable file
    :param logging: logging enabled or disabled
    :param log_level: log_level to be disabled (error, warning, critical, info, debug)
    :return: True/False - True if successful otherwise return false
    """
    extra_vars = {"PROXY_DATA_FILE": PROXY_DATA_FILE,
                  "VARIABLE_FILE": VARIABLE_FILE,
                  "logging": logging,
                  "log_level": log_level,
                  "file_path": file_path,
                  "logging_port": logging_port,
                  "Project_name": Project_name}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_cpu_manager_configuration_play(playbook, PROXY_DATA_FILE,
                                          VARIABLE_FILE):
    """
    Configure CPU management policies in Cluster
    """
    extra_vars = {"PROXY_DATA_FILE": PROXY_DATA_FILE,
                  "VARIABLE_FILE": VARIABLE_FILE}
    logger.info("Arguments are %s", str(extra_vars))

    retval = execute_system_command_with_subprocess(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_k8(playbook, service_subnet, pod_subnet,
                               networking_plugin, PROXY_DATA_FILE,
                               VARIABLE_FILE, SRC_PACKAGE_PATH, CURRENT_DIR,
                               Git_branch, Project_name):
    """
    Applies ansible playbooks to the listed hosts with provided IPs
    :param ansible_configs: a list of Ansible host configurations
    :param playbook_path: the path of the playbook  file
    :return: t/f - true if successful
    """
    extra_vars = {"PROXY_DATA_FILE": PROXY_DATA_FILE,
                  "VARIABLE_FILE": VARIABLE_FILE,
                  "service_subnet": service_subnet,
                  "pod_subnet": pod_subnet,
                  "networking_plugin": networking_plugin,
                  "SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "Git_branch": Git_branch,
                  "CURRENT_DIR": CURRENT_DIR,
                  "Project_name": Project_name}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_inventory(playbook, node_type, host_name,
                                      SRC_PACKAGE_PATH, VARIABLE_FILE,
                                      Project_name):
    extra_vars = {"VARIABLE_FILE": VARIABLE_FILE,
                  "node_type": node_type,
                  "host_name": host_name,
                  "SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "Project_name": Project_name}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_new_inventory(playbook, ip, host_name,
                                          SRC_PACKAGE_PATH, VARIABLE_FILE,
                                          CURRENT_DIR, Project_name):
    extra_vars = {"VARIABLE_FILE": VARIABLE_FILE,
                  "ip": ip,
                  "host_name": host_name,
                  "SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "CURRENT_DIR": CURRENT_DIR,
                  "Project_name": Project_name}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_update_user_list(playbook, user_name,
                                             user_password, user_id,
                                             SRC_PACKAGE_PATH):
    extra_vars = {"user_name": user_name,
                  "user_password": user_password,
                  "user_id": user_id,
                  "SRC_PACKAGE_PATH": SRC_PACKAGE_PATH}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_authentication(playbook, host_name,
                                           SRC_PACKAGE_PATH, VARIABLE_FILE):
    extra_vars = {"VARIABLE_FILE": VARIABLE_FILE,
                  "SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "host_name": host_name}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_etcd_changes(playbook, host_name, ip,
                                         SRC_PACKAGE_PATH, VARIABLE_FILE):
    extra_vars = {"VARIABLE_FILE": VARIABLE_FILE,
                  "SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "host_name": host_name,
                  "ip": ip}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_ceph_storage(playbook, host_name,
                                         master_host_name, SRC_PACKAGE_PATH,
                                         VARIABLE_FILE, storage,
                                         PROXY_DATA_FILE, node_type):
    extra_vars = {"PROXY_DATA_FILE": PROXY_DATA_FILE,
                  "host_name": host_name,
                  "master_host_name": master_host_name,
                  "SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "VARIABLE_FILE": VARIABLE_FILE,
                  "storage": storage,
                  "node_type": node_type}
    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_ceph_volume2(playbook, host_name,
                                         SRC_PACKAGE_PATH, VARIABLE_FILE,
                                         ceph_storage_size, ceph_claim_name,
                                         PROXY_DATA_FILE, controller_host_name,
                                         ceph_controller_ip):
    extra_vars = {"PROXY_DATA_FILE": PROXY_DATA_FILE,
                  "VARIABLE_FILE": VARIABLE_FILE,
                  "SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "host_name": host_name,
                  "ceph_storage_size": ceph_storage_size,
                  "ceph_claim_name": ceph_claim_name,
                  "controller_host_name": controller_host_name,
                  "ceph_controller_ip": ceph_controller_ip}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_ceph_volume_first(playbook, host_name,
                                              SRC_PACKAGE_PATH,
                                              VARIABLE_FILE,
                                              PROXY_DATA_FILE,
                                              host_ip):
    extra_vars = {"PROXY_DATA_FILE": PROXY_DATA_FILE,
                  "VARIABLE_FILE": VARIABLE_FILE,
                  "SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "host_name": host_name,
                  "host_ip": host_ip}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_ceph_mon(playbook, master_host_name,
                                     VARIABLE_FILE, PROXY_DATA_FILE):
    extra_vars = {"PROXY_DATA_FILE": PROXY_DATA_FILE,
                  "VARIABLE_FILE": VARIABLE_FILE,
                  "master_host_name": master_host_name}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_ceph_deploy(playbook, host_name,
                                        master_host_name, VARIABLE_FILE,
                                        PROXY_DATA_FILE, user_id, passwd):
    extra_vars = {"PROXY_DATA_FILE": PROXY_DATA_FILE,
                  "VARIABLE_FILE": VARIABLE_FILE,
                  "master_host_name": master_host_name,
                  "host_name": host_name,
                  "user_id": user_id,
                  "passwd": passwd}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_ceph_deploy_admin(playbook, host_name,
                                              master_host_name,
                                              VARIABLE_FILE,
                                              PROXY_DATA_FILE):
    extra_vars = {"PROXY_DATA_FILE": PROXY_DATA_FILE,
                  "VARIABLE_FILE": VARIABLE_FILE,
                  "master_host_name": master_host_name,
                  "host_name": host_name}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_ceph_volume(playbook, host_name,
                                        SRC_PACKAGE_PATH, VARIABLE_FILE,
                                        PROXY_DATA_FILE, osd_host_name,
                                        user_id, passwd, osd_ip):
    extra_vars = {"PROXY_DATA_FILE": PROXY_DATA_FILE,
                  "VARIABLE_FILE": VARIABLE_FILE,
                  "SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "host_name": host_name,
                  "osd_ip": osd_ip,
                  "osd_host_name": osd_host_name,
                  "user_id": user_id,
                  "passwd": passwd}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_node_labeling(playbook, master_hostname,
                                          hostname, label_key, label_value,
                                          PROXY_DATA_FILE):
    extra_vars = {"master_hostname": master_hostname,
                  "hostname": hostname,
                  "label_key": label_key,
                  "label_value": label_value,
                  "PROXY_DATA_FILE": PROXY_DATA_FILE}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_delete_secret(playbook, master_hostname, PROXY_DATA_FILE):
    extra_vars = {"master_hostname": master_hostname,
                  "PROXY_DATA_FILE": PROXY_DATA_FILE}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_persistent_volume(playbook, host_name,
                                              SRC_PACKAGE_PATH,
                                              VARIABLE_FILE,
                                              storage_size, claim_name,
                                              PROXY_DATA_FILE):
    extra_vars = {"VARIABLE_FILE": VARIABLE_FILE,
                  "SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "host_name": host_name,
                  "storage_size": storage_size,
                  "claim_name": claim_name,
                  "PROXY_DATA_FILE": PROXY_DATA_FILE}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_weave_scope(playbook, host_name,
                                        SRC_PACKAGE_PATH,
                                        VARIABLE_FILE,
                                        PROXY_DATA_FILE):
    extra_vars = {"VARIABLE_FILE": VARIABLE_FILE,
                  "SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "host_name": host_name,
                  "PROXY_DATA_FILE": PROXY_DATA_FILE}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_delete_node(playbook, host_name,
                                        SRC_PACKAGE_PATH, VARIABLE_FILE,
                                        Project_name):
    extra_vars = {"VARIABLE_FILE": VARIABLE_FILE,
                  "SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "host_name": host_name,
                  "Project_name": Project_name}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_kube_proxy(playbook, host_name,
                                       SRC_PACKAGE_PATH,
                                       VARIABLE_FILE,
                                       PROXY_DATA_FILE):

    extra_vars = {"VARIABLE_FILE": VARIABLE_FILE,
                  "SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "host_name": host_name,
                  "PROXY_DATA_FILE": PROXY_DATA_FILE}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval


def launch_delete_host_k8(playbook, ip, host_name, HOST_FILE_PATH,
                          ANSIBLE_HOST_FILE_PATH, VARIABLE_FILE,
                          Project_name, multus_enabled):
    extra_vars = {"ANSIBLE_HOST_FILE_PATH": ANSIBLE_HOST_FILE_PATH,
                  "VARIABLE_FILE": VARIABLE_FILE,
                  "HOST_FILE_PATH": HOST_FILE_PATH,
                  "host_name": host_name,
                  "multus_enabled": multus_enabled,
                  "ip": ip,
                  "Project_name": Project_name}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_delete_project_folder(playbook, VARIABLE_FILE,
                                 SRC_PACKAGE_PATH, Project_name,
                                 PROXY_DATA_FILE):
    extra_vars = {"VARIABLE_FILE": VARIABLE_FILE,
                  "SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "Project_name": Project_name,
                  "PROXY_DATA_FILE": PROXY_DATA_FILE}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_clean_k8(playbook, SRC_PACKAGE_PATH,
                                     VARIABLE_FILE, PROXY_DATA_FILE,
                                     Git_branch, Project_name):
    extra_vars = {"PROXY_DATA_FILE": PROXY_DATA_FILE,
                  "VARIABLE_FILE": VARIABLE_FILE,
                  "SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "Git_branch": Git_branch,
                  "Project_name": Project_name}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook(playbook, target, host_name, PROXY_DATA_FILE,
                            VARIABLE_FILE, APT_ARCHIVES_SRC,
                            SRC_PACKAGE_PATH, registry_port):
    extra_vars = {"PROXY_DATA_FILE": PROXY_DATA_FILE,
                  "SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "host_name": host_name,
                  "target": target,
                  "VARIABLE_FILE": VARIABLE_FILE,
                  "APT_ARCHIVES_SRC": APT_ARCHIVES_SRC,
                  "registry_port": registry_port}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_creating_docker_repo(playbook, PROXY_DATA_FILE,
                                                 VARIABLE_FILE, docker_ip,
                                                 docker_port,
                                                 APT_ARCHIVES_SRC,
                                                 SRC_PACKAGE_PATH):
    extra_vars = {"PROXY_DATA_FILE": PROXY_DATA_FILE,
                  "VARIABLE_FILE": VARIABLE_FILE,
                  "SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "docker_ip": docker_ip,
                  "docker_port": docker_port,
                  "APT_ARCHIVES_SRC": APT_ARCHIVES_SRC}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def creating_inventory_file(playbook, SRC_PACKAGE_PATH, VARIABLE_FILE,
                            CURRENT_DIR, Project_name):
    extra_vars = {"VARIABLE_FILE": VARIABLE_FILE,
                  "SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "CURRENT_DIR": CURRENT_DIR,
                  "Project_name": Project_name}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_docker_conf(playbook, target, host_name,
                                        PROXY_DATA_FILE, VARIABLE_FILE,
                                        docker_ip, docker_port):
    extra_vars = {"PROXY_DATA_FILE": PROXY_DATA_FILE,
                  "VARIABLE_FILE": VARIABLE_FILE,
                  "target": target,
                  "host_name": host_name,
                  "docker_ip": docker_ip,
                  "docker_port": docker_port}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_metrics_server(playbook, ip, host_name,
                                           PROXY_DATA_FILE):
    """
    function  for metrics server
    """
    extra_vars = {"PROXY_DATA_FILE": PROXY_DATA_FILE,
                  "host_name": host_name,
                  "ip": ip}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_metrics_server_clean(playbook, ip, host_name, PROXY_DATA_FILE):
    """
    function  for metrics server remove
    """
    extra_vars = {"host_name": host_name,
                  "ip": ip,
                  "PROXY_DATA_FILE": PROXY_DATA_FILE}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_create_crd_network(playbook, ip, host_name,
                                               SRC_PACKAGE_PATH,
                                               PROXY_DATA_FILE):
    extra_vars = {"SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "host_name": host_name,
                  "ip": ip,
                  "PROXY_DATA_FILE": PROXY_DATA_FILE}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_master_multus(playbook, ip, host_name,
                                          networking_plugin,
                                          SRC_PACKAGE_PATH,
                                          PROXY_DATA_FILE):
    extra_vars = {"SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "networking_plugin": networking_plugin,
                  "host_name": host_name,
                  "ip": ip,
                  "PROXY_DATA_FILE": PROXY_DATA_FILE}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_scp_multus(playbook, ip, host_name,
                                       networking_plugin, SRC_PACKAGE_PATH):
    extra_vars = {"SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "networking_plugin": networking_plugin,
                  "host_name": host_name,
                  "ip": ip}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_node_multus(playbook, ip, host_name,
                                        networking_plugin, SRC_PACKAGE_PATH):
    extra_vars = {"SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "networking_plugin": networking_plugin,
                  "host_name": host_name,
                  "ip": ip}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_master_flannel(playbook, ip, host_name,
                                           networking_plugin, network,
                                           subnetLen, vni, SRC_PACKAGE_PATH):
    extra_vars = {"SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "networking_plugin": networking_plugin,
                  "network": network,
                  "subnetLen": subnetLen,
                  "vni": vni,
                  "host_name": host_name,
                  "ip": ip}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_node_flannel(playbook, ip, host_name,
                                         networking_plugin, network,
                                         subnetLen, vni, master_ip,
                                         SRC_PACKAGE_PATH):
    extra_vars = {"SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "networking_plugin": networking_plugin,
                  "network": network,
                  "subnetLen": subnetLen,
                  "vni": vni,
                  "host_name": host_name,
                  "master_ip": master_ip,
                  "ip": ip}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_create_flannel_networks(playbook, ip, host_name,
                                                    networkName, vni,
                                                    vniTemp, SRC_PACKAGE_PATH,
                                                    PROXY_DATA_FILE):
    extra_vars = {"SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "networkName": networkName,
                  "vniTemp": vniTemp,
                  "vni": vni,
                  "host_name": host_name,
                  "ip": ip,
                  "PROXY_DATA_FILE": PROXY_DATA_FILE}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_flannel_daemon(playbook, ip, network, cidr,
                                           masterPlugin, SRC_PACKAGE_PATH):
    extra_vars = {"SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "masterPlugin": masterPlugin,
                  "cidr": cidr,
                  "network": network,
                  "ip": ip}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_create_flannel_interface(playbook, ip, host_name,
                                                     networkName, network,
                                                     masterPlugin,
                                                     SRC_PACKAGE_PATH,
                                                     PROXY_DATA_FILE):
    extra_vars = {"SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "masterPlugin": masterPlugin,
                  "network": network,
                  "networkName": networkName,
                  "host_name": host_name,
                  "ip": ip,
                  "PROXY_DATA_FILE": PROXY_DATA_FILE}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_copy_flannel_cni(playbook, ip, host_name,
                                             network, SRC_PACKAGE_PATH):
    extra_vars = {"SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "network": network,
                  "host_name": host_name,
                  "ip": ip}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_clean_sriov_rc_local(playbook, host_name, sriov_intf):
    extra_vars = {"sriov_intf": sriov_intf,
                  "host_name": host_name}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_enable_sriov(playbook, host_name, sriov_intf,
                                         script_path, networking_plugin):
    extra_vars = {"networking_plugin": networking_plugin,
                  "script_path": script_path,
                  "sriov_intf": sriov_intf,
                  "host_name": host_name}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_build_sriov(playbook, SRC_PACKAGE_PATH,
                                        PROXY_DATA_FILE):
    extra_vars = {"PROXY_DATA_FILE": PROXY_DATA_FILE,
                  "SRC_PACKAGE_PATH": SRC_PACKAGE_PATH}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_sriov_install(playbook, host_name,
                                          SRC_PACKAGE_PATH):
    extra_vars = {"host_name": host_name,
                  "SRC_PACKAGE_PATH": SRC_PACKAGE_PATH}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_sriov_dhcp_crd_nw(playbook,
                                              playbook_path_sriov_conf,
                                              sriov_intf, host_name, nw_name,
                                              PROXY_DATA_FILE):
    extra_vars = {"playbook_path_sriov_conf": playbook_path_sriov_conf,
                  "sriov_intf": sriov_intf,
                  "host_name": host_name,
                  "nw_name": nw_name,
                  "PROXY_DATA_FILE": PROXY_DATA_FILE}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_sriov_crd_nw(playbook, playbook_path_sriov_conf,
                                         sriov_intf, host_name, nw_name,
                                         s_rng, e_rng, subnet, gw,
                                         masterPlugin):
    extra_vars = {"playbook_path_sriov_conf": playbook_path_sriov_conf,
                  "sriov_intf": sriov_intf,
                  "host_name": host_name,
                  "nw_name": nw_name,
                  "s_rng": s_rng,
                  "e_rng": e_rng,
                  "subnet": subnet,
                  "gw": gw,
                  "masterPlugin": masterPlugin}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_build_sriov_dpdk(playbook, SRC_PACKAGE_PATH,
                                             PROXY_DATA_FILE):
    extra_vars = {"PROXY_DATA_FILE": PROXY_DATA_FILE,
                  "SRC_PACKAGE_PATH": SRC_PACKAGE_PATH}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_sriov_dpdk_install(playbook, host_name,
                                               SRC_PACKAGE_PATH):
    extra_vars = {"host_name": host_name,
                  "SRC_PACKAGE_PATH": SRC_PACKAGE_PATH}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_dpdk_driver_load(playbook, host_name,
                                             dpdk_driver):
    extra_vars = {"host_name": host_name,
                  "dpdk_driver": dpdk_driver}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_sriov_dpdk_crd_nw(playbook,
                                              playbook_path_sriov_conf,
                                              sriov_intf, host_name, nw_name,
                                              dpdk_driver, dpdk_tool,
                                              node_hostname, masterPlugin):
    extra_vars = {"playbook_path_sriov_conf": playbook_path_sriov_conf,
                  "sriov_intf": sriov_intf,
                  "host_name": host_name,
                  "nw_name": nw_name,
                  "dpdk_driver": dpdk_driver,
                  "dpdk_tool": dpdk_tool,
                  "node_hostname": node_hostname,
                  "masterPlugin": masterPlugin}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval


def launch_ansible_playbook_node_vlantag_interface(playbook, host,
                                                   parentInterface,
                                                   vlanId, ip):
    extra_vars = {"host": host,
                  "parentInterface": parentInterface,
                  "vlanId": vlanId,
                  "ip": ip}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_node_vlantag_interface_removal(playbook, host,
                                                           parentInterface,
                                                           vlanId):
    extra_vars = {"host": host,
                  "parentInterface": parentInterface,
                  "vlanId": vlanId}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_network_creation(playbook, host, network_name,
                                             interface_node, subnet,
                                             rangeStart, rangeEnd, dst,
                                             gateway,
                                             PROXY_DATA_FILE):
    extra_vars = {"host": host,
                  "network_name": network_name,
                  "interface_node": interface_node,
                  "subnet": subnet,
                  "rangeStart": rangeStart,
                  "rangeEnd": rangeEnd,
                  "dst": dst,
                  "gateway": gateway,
                  "PROXY_DATA_FILE": PROXY_DATA_FILE}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_network_removal(playbook, host, network_name, PROXY_DATA_FILE):
    extra_vars = {"host": host,
                  "network_name": network_name,
                  "PROXY_DATA_FILE": PROXY_DATA_FILE}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_network_dhcp_creation(playbook, host,
                                                  network_name, interface_node,
                                                  PROXY_DATA_FILE):
    extra_vars = {"host": host,
                  "network_name": network_name,
                  "interface_node": interface_node,
                  "PROXY_DATA_FILE": PROXY_DATA_FILE}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_dhcp_daemon_creation(playbook, host):
    extra_vars = {"host": host}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_dhcp_daemon_removal(playbook, host):
    extra_vars = {"host": host}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_clean_docker(playbook,host_name):
    """
    function added for cleaning the docker on cluster nodes
    :param playbook:
    :param host_name:
    :return:
    """
    extra_vars = {"host_name": host_name}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command_with_subprocess(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_create_weave_network(playbook, ip, host_name,
                                                 networkName, subnet,
                                                 masterPlugin,
                                                 SRC_PACKAGE_PATH,
                                                 PROXY_DATA_FILE):
    extra_vars = {"SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "masterPlugin": masterPlugin,
                  "subnet": subnet,
                  "networkName": networkName,
                  "host_name": host_name,
                  "ip": ip,
                  "PROXY_DATA_FILE": PROXY_DATA_FILE}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_delete_weave_conf(playbook, ip, host_name,
                                              networking_plugin,
                                              SRC_PACKAGE_PATH):
    extra_vars = {"SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "networking_plugin": networking_plugin,
                  "host_name": host_name,
                  "ip": ip}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_copy_weave_cni(playbook, ip, host_name,
                                           subnet, SRC_PACKAGE_PATH):
    extra_vars = {"SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "subnet": subnet,
                  "host_name": host_name,
                  "ip": ip}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_delete_conf_files(playbook, ip, host_name,
                                              networking_plugin,
                                              SRC_PACKAGE_PATH):
    extra_vars = {"SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "networking_plugin": networking_plugin,
                  "host_name": host_name,
                  "ip": ip}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_create_default_network(playbook, ip, host_name,
                                                   networkName, subnet,
                                                   networking_plugin,
                                                   masterPlugin,
                                                   SRC_PACKAGE_PATH,
                                                   PROXY_DATA_FILE):
    extra_vars = {"SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "masterPlugin": masterPlugin,
                  "networking_plugin": networking_plugin,
                  "subnet": subnet,
                  "networkName": networkName,
                  "host_name": host_name,
                  "ip": ip,
                  "PROXY_DATA_FILE": PROXY_DATA_FILE}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval


def launch_ansible_playbook_weave_reclaim_ip(playbook, ip, host_name,
                                             node_hostname,
                                             SRC_PACKAGE_PATH):
    extra_vars = {"SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "node_hostname": node_hostname,
                  "host_name": host_name,
                  "ip": ip}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_weave_forget_ip(playbook, ip, host_name,
                                            node_hostname1, SRC_PACKAGE_PATH):
    extra_vars = {"SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                  "node_hostname1": node_hostname1,
                  "host_name": host_name,
                  "ip": ip}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval


def launch_ansible_playbook_install_dhcp_daemon(playbook, host):
    extra_vars = {"host": host}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_dhcp_cleanup_network(playbook, host):
    extra_vars = {"host": host}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval

def launch_ansible_playbook_remove_sriov_networks(playbook, host, network_name):
    extra_vars = {"host": host,
                  "network_name": network_name}

    logger.info("Arguments are %s", str(extra_vars))
    retval = execute_system_command(playbook, extra_vars)
    logger.info('Exit')
    return retval


class KubectlPlayBookLauncher(object):
    def __init__(self):
        pass

    def launch_ansible_playbook_install_kubectl(self, playbook, ip, host_name,
                                                ha_enabled, Project_name, lb_ip,
                                                VARIABLE_FILE, SRC_PACKAGE_PATH,
                                                PROXY_DATA_FILE):
        """
        function added for installing kubectl
        :param playbook:
        :param ip:
        :param host_name:
        :param ha_enabled:
        :param Project_name:
        :param lb_ip:
        :param VARIABLE_FILE:
        :param SRC_PACKAGE_PATH:
        :param PROXY_DATA_FILE:
        :return:
        """
        extra_vars = {"SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                      "VARIABLE_FILE": VARIABLE_FILE,
                      "lb_ip": lb_ip,
                      "Project_name": Project_name,
                      "ha_enabled": ha_enabled,
                      "host_name": host_name,
                      "ip": ip,
                      "PROXY_DATA_FILE": PROXY_DATA_FILE}
        logger.info("Arguments are %s", str(extra_vars))

        retval = execute_system_command(playbook, extra_vars)
        logger.info('Exit')
        return retval

    def launch_ansible_playbook_set_kubectl_context(self, playbook,
                                                    Project_name,
                                                    VARIABLE_FILE,
                                                    SRC_PACKAGE_PATH,
                                                    PROXY_DATA_FILE):
        """
        function added to set kubectl context
        :param Project_name:
        :param VARIABLE_FILE:
        :param SRC_PACKAGE_PATH:
        :param PROXY_DATA_FILE:
        :return:
        """
        extra_vars = {"SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                      "VARIABLE_FILE": VARIABLE_FILE,
                      "Project_name": Project_name,
                      "PROXY_DATA_FILE": PROXY_DATA_FILE}
        logger.info("Arguments are %s", str(extra_vars))

        retval = execute_system_command(playbook, extra_vars)
        logger.info('Exit')
        return retval

class CleanUpMultusPlayBookLauncher(object):
    def __init__(self):
        pass

    def launch_ansible_playbook_delete_flannel_interfaces(self, playbook, ip,
                                                          host_name, node_type,
                                                          networkName,
                                                          SRC_PACKAGE_PATH,
                                                          PROXY_DATA_FILE):
        """
        function added for installing kubectl
        :param playbook:
        :param ip:
        :param host_name:
        :param node_type:
        :param networkName:
        :param SRC_PACKAGE_PATH:
        :param PROXY_DATA_FILE:
        :return:
        """
        extra_vars = {"SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                      "networkName": networkName,
                      "node_type": node_type,
                      "host_name": host_name,
                      "ip": ip,
                      "PROXY_DATA_FILE": PROXY_DATA_FILE}

        logger.info("Arguments are %s", str(extra_vars))
        retval = execute_system_command_with_subprocess(playbook, extra_vars)
        logger.info('Exit')
        return retval


    def launch_ansible_playbook_delete_weave_interface(self, playbook, ip,
                                                       host_name, node_type,
                                                       networkName,
                                                       SRC_PACKAGE_PATH,
                                                       PROXY_DATA_FILE):
        """
        function added for installing kubectl
        :param playbook:
        :param ip:
        :param host_name:
        :param node_type:
        :param networkName:
        :param SRC_PACKAGE_PATH:
        :param PROXY_DATA_FILE:
        :return:
        """
        extra_vars = {"SRC_PACKAGE_PATH": SRC_PACKAGE_PATH,
                      "networkName": networkName,
                      "node_type": node_type,
                      "host_name": host_name,
                      "ip": ip,
                      "PROXY_DATA_FILE": PROXY_DATA_FILE}

        logger.info("Arguments are %s", str(extra_vars))
        retval = execute_system_command_with_subprocess(playbook, extra_vars)
        logger.info('Exit')
        return retval

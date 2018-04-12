#* Copyright 2018 ARICENT HOLDINGS LUXEMBOURG SARL and Cable Television
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
#This script is responsible for calling all the playbooks responsible for deploying kubernetes

import logging

from collections import namedtuple

import os
#import paramiko
from ansible.executor.playbook_executor import PlaybookExecutor
from ansible.parsing.dataloader import DataLoader
from ansible.vars import VariableManager
from ansible.inventory import Inventory
import ansible.constants
#from ansible.executor.playbook_executor import PlaybookExecutor
#from ansible.parsing.dataloader import DataLoader
#from ansible.vars import VariableManager
#from ansible.inventory import Inventory
#import ansible.constants

__author__ = '_ARICENT'

logger = logging.getLogger('ansible_playbook_operations')

def __launch_ansible_playbook_k8(playbook,service_subnet,pod_subnet,networking_plugin,PROXY_DATA_FILE,VARIABLE_FILE,SRC_PACKAGE_PATH,CURRENT_DIR,Git_branch,Project_name):
#def __launch_ansible_playbook_k8(iplist, playbook, ip,host_name):


    """
    Applies ansible playbooks to the listed hosts with provided IPs
    :param ansible_configs: a list of Ansible host configurations
    :param playbook_path: the path of the playbook  file
    :return: t/f - true if successful
    """
    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"service_subnet\": \"'+service_subnet+'\",\"pod_subnet\": \"'+pod_subnet+'\",\"networking_plugin\": \"'+networking_plugin+'\",\"PROXY_DATA_FILE\": \"'+PROXY_DATA_FILE+'\",\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\",\"Git_branch\": \"'+Git_branch+'\",\"Project_name\": \"'+Project_name+'\",\"CURRENT_DIR\": \"'+CURRENT_DIR+'\"}\''
    logger.info(command) 
    os.system(command)
    return True

def __launch_ansible_playbook_inventory(playbook,node_type,host_name,SRC_PACKAGE_PATH,VARIABLE_FILE,Project_name):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"node_type\": \"'+node_type+'\",\"host_name\": \"'+host_name+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\",\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\",\"Project_name\": \"'+Project_name+'\"}\''
    logger.info(command) 
    print "node_type" 
    print node_type 
    os.system(command)
    return True

def __launch_ansible_playbook_new_inventory(playbook,ip,host_name,SRC_PACKAGE_PATH,VARIABLE_FILE,CURRENT_DIR,Project_name):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"ip\": \"'+ip+'\",\"host_name\": \"'+host_name+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\",\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\",\"CURRENT_DIR\": \"'+CURRENT_DIR+'\",\"Project_name\": \"'+Project_name+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_update_user_list(playbook,user_name,user_password,user_id,SRC_PACKAGE_PATH):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"user_name\": \"'+user_name+'\",\"user_password\": \"'+user_password+'\",\"user_id\": \"'+user_id+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\"}\''
    logger.info(command)
    os.system(command)
    return True
def __launch_ansible_playbook_authentication(playbook,host_name,SRC_PACKAGE_PATH,VARIABLE_FILE):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"host_name\": \"'+host_name+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\",\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_etcd_changes(playbook,host_name,ip,SRC_PACKAGE_PATH,VARIABLE_FILE):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"host_name\": \"'+host_name+'\",\"ip\": \"'+ip+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\",\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_ceph_storage(playbook,host_name,master_host_name,SRC_PACKAGE_PATH,VARIABLE_FILE,storage,PROXY_DATA_FILE,node_type):
    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"host_name\": \"'+host_name+'\",\"master_host_name\": \"'+master_host_name+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\",\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\",\"PROXY_DATA_FILE\": \"'+PROXY_DATA_FILE+'\",\"storage\": \"'+storage+'\",\"node_type\": \"'+node_type+'\"}\''
    logger.info(command)
    os.system(command)
    return True
def __launch_ansible_playbook_ceph_volume2(playbook,host_name,SRC_PACKAGE_PATH,VARIABLE_FILE,ceph_storage_size,ceph_claim_name,PROXY_DATA_FILE,controller_host_name,ceph_controller_ip):
    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"host_name\": \"'+host_name+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\",\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\",\"PROXY_DATA_FILE\": \"'+PROXY_DATA_FILE+'\",\"ceph_storage_size\": \"'+ceph_storage_size+'\",\"ceph_claim_name\": \"'+ceph_claim_name+'\",\"controller_host_name\": \"'+controller_host_name+'\",\"ceph_controller_ip\": \"'+ceph_controller_ip+'\"}\''
    logger.info(command)
    os.system(command)
    return True
def __launch_ansible_playbook_ceph_volume_first(playbook,host_name,SRC_PACKAGE_PATH,VARIABLE_FILE,PROXY_DATA_FILE,host_ip):
    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"host_name\": \"'+host_name+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\",\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\",\"PROXY_DATA_FILE\": \"'+PROXY_DATA_FILE+'\",\"host_ip\": \"'+host_ip+'\"}\''
    logger.info(command)
    os.system(command)
    return True
def __launch_ansible_playbook_ceph_mon(playbook,master_host_name,VARIABLE_FILE,PROXY_DATA_FILE):
    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"master_host_name\": \"'+master_host_name+'\",\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\",\"PROXY_DATA_FILE\": \"'+PROXY_DATA_FILE+'\"}\''
    logger.info(command)
    os.system(command)
    return True
def __launch_ansible_playbook_ceph_deploy(playbook,host_name,master_host_name,VARIABLE_FILE,PROXY_DATA_FILE,user_id, passwd):
    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"host_name\": \"'+host_name+'\",\"master_host_name\": \"'+master_host_name+'\",\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\",\"PROXY_DATA_FILE\": \"'+PROXY_DATA_FILE+'\",\"user_id\": \"'+user_id+'\",\"passwd\": \"'+passwd+'\"}\''
    logger.info(command)
    os.system(command)
    return True
def __launch_ansible_playbook_ceph_deploy_admin(playbook,host_name,master_host_name,VARIABLE_FILE,PROXY_DATA_FILE):
    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"host_name\": \"'+host_name+'\",\"master_host_name\": \"'+master_host_name+'\",\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\",\"PROXY_DATA_FILE\": \"'+PROXY_DATA_FILE+'\"}\''
    logger.info(command)
    os.system(command)
    return True
def __launch_ansible_playbook_ceph_volume(playbook,host_name,SRC_PACKAGE_PATH,VARIABLE_FILE,PROXY_DATA_FILE,osd_host_name,user_id,passwd,osd_ip):
    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"host_name\": \"'+host_name+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\",\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\",\"PROXY_DATA_FILE\": \"'+PROXY_DATA_FILE+'\",\"osd_host_name\": \"'+osd_host_name+'\",\"user_id\": \"'+user_id+'\",\"passwd\": \"'+passwd+'\",\"osd_ip\": \"'+osd_ip+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_node_labeling(playbook,master_hostname,hostname,label_key,label_value):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"master_hostname\": \"'+master_hostname+'\",\"hostname\": \"'+hostname+'\",\"label_key\": \"'+label_key+'\",\"label_value\": \"'+label_value+'\"}\''
    logger.info(command)
    os.system(command)
    return True
def __launch_ansible_playbook_delete_secret(playbook,master_hostname):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"master_hostname\": \"'+master_hostname+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_persistent_volume(playbook,host_name,SRC_PACKAGE_PATH,VARIABLE_FILE,storage_size,claim_name):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"host_name\": \"'+host_name+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\",\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\",\"storage_size\": \"'+storage_size+'\",\"claim_name\": \"'+claim_name+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_weave_scope(playbook,host_name,SRC_PACKAGE_PATH,VARIABLE_FILE):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"host_name\": \"'+host_name+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\",\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_delete_node(playbook,host_name,SRC_PACKAGE_PATH,VARIABLE_FILE,Project_name):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"Project_name\": \"'+Project_name+'\",\"host_name\": \"'+host_name+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\",\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\"}\''
    logger.info(command)
    os.system(command)
    return True
def __launch_ansible_playbook_dynamic_k8_nodes_delete(playbook,host_name,SRC_PACKAGE_PATH,VARIABLE_FILE,PROXY_DATA_FILE,master_hostname,Project_name):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"host_name\": \"'+host_name+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\",\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\",\"PROXY_DATA_FILE\": \"'+PROXY_DATA_FILE+'\",\"master_hostname\": \"'+master_hostname+'\",\"Project_name\": \"'+Project_name+'\"}\''
    logger.info(command)
    os.system(command)
    return True
def __launch_ansible_playbook_dynamic_k8_nodes(playbook,host_name,SRC_PACKAGE_PATH,VARIABLE_FILE,PROXY_DATA_FILE,Project_name):

   # command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"host_name\": \"'+host_name+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\",\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\",\"PROXY_DATA_FILE\": \"'+PROXY_DATA_FILE+'\"}\''
    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"host_name\": \"'+host_name+'\",\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\",\"Project_name\": \"'+Project_name+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_delete_host_k8(playbook,ip,host_name,HOST_FILE_PATH,ANSIBLE_HOST_FILE_PATH,VARIABLE_FILE,Project_name):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"ip\": \"'+ip+'\",\"host_name\": \"'+host_name+'\",\"HOST_FILE_PATH\": \"'+HOST_FILE_PATH+'\",\"ANSIBLE_HOST_FILE_PATH\": \"'+ANSIBLE_HOST_FILE_PATH+'\",\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\",\"Project_name\": \"'+Project_name+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_delete_project_folder(playbook,VARIABLE_FILE,Project_name):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\",\"Project_name\": \"'+Project_name+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_clean_k8(playbook,SRC_PACKAGE_PATH,VARIABLE_FILE,PROXY_DATA_FILE,Git_branch,Project_name):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\",\"PROXY_DATA_FILE\": \"'+PROXY_DATA_FILE+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\",\"Git_branch\": \"'+Git_branch+'\",\"Project_name\": \"'+Project_name+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook(playbook,target,host_name,PROXY_DATA_FILE,VARIABLE_FILE,APT_ARCHIVES_SRC,SRC_PACKAGE_PATH,registry_port):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"target\": \"'+target+'\",\"host_name\": \"'+host_name+'\",\"PROXY_DATA_FILE\": \"'+PROXY_DATA_FILE+'\",\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\",\"APT_ARCHIVES_SRC\": \"'+APT_ARCHIVES_SRC+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\",\"registry_port\": \"'+registry_port+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_creating_docker_repo(playbook,PROXY_DATA_FILE,VARIABLE_FILE,docker_ip,docker_port,APT_ARCHIVES_SRC,SRC_PACKAGE_PATH):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"PROXY_DATA_FILE\": \"'+PROXY_DATA_FILE+'\",\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\",\"docker_ip\": \"'+docker_ip+'\",\"docker_port\": \"'+docker_port+'\",\"APT_ARCHIVES_SRC\": \"'+APT_ARCHIVES_SRC+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_dynamic_docker_conf(playbook,target,host_name,master_ip,PROXY_DATA_FILE,VARIABLE_FILE):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"target\": \"'+target+'\",\"master_ip\": \"'+master_ip+'\",\"host_name\": \"'+host_name+'\",\"PROXY_DATA_FILE\": \"'+PROXY_DATA_FILE+'\",\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __creating_inventory_file(playbook,SRC_PACKAGE_PATH,VARIABLE_FILE,CURRENT_DIR,Project_name):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\",\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\",\"CURRENT_DIR\": \"'+CURRENT_DIR+'\",\"Project_name\": \"'+Project_name+'\"}\''
    logger.info(command)
    os.system(command)
    return True


def __launch_ansible_playbook_docker_conf(playbook,target,host_name,PROXY_DATA_FILE,VARIABLE_FILE,docker_ip,docker_port):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"target\": \"'+target+'\",\"host_name\": \"'+host_name+'\",\"PROXY_DATA_FILE\": \"'+PROXY_DATA_FILE+'\",\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\",\"docker_ip\": \"'+docker_ip+'\",\"docker_port\": \"'+docker_port+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_istio(playbook,inventory_file_path,PROXY_DATA_FILE):

    command = '/usr/bin/ansible-playbook '+ playbook +' -i '+ inventory_file_path +' --extra-vars=\'{\"PROXY_DATA_FILE\": \"'+PROXY_DATA_FILE+'\",\"INVENTORY_PATH\": \"'+inventory_file_path+'\"}\''
    logger.info(command)
    os.system(command)
    return True
def __launch_ansible_playbook_uninstall_istio(playbook,host_name,SRC_PACKAGE_PATH):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"host_name\": \"'+host_name+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\"}\''
    logger.info(command)
    os.system(command)
    return True

#def __launch_ansible_playbook_proxy(playbook,PROXY_DATA_FILE,VARIABLE_FILE):
#
#    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"PROXY_DATA_FILE\": \"'+PROXY_DATA_FILE+'\",\"VARIABLE_FILE\": \"'+VARIABLE_FILE+'\"}\''
#    logger.info(command)
#    os.system(command)
#    return True
def __launch_ansible_playbook_ambassador(playbook,inventory_file_path,PROXY_DATA_FILE,ambassador_rbac):
    command = '/usr/bin/ansible-playbook '+ playbook +' -i '+ inventory_file_path +' --extra-vars=\'{\"PROXY_DATA_FILE\": \"'+PROXY_DATA_FILE+'\",\"INVENTORY_PATH\": \"'+inventory_file_path+'\",\"ambassador_rbac\": \"'+ambassador_rbac+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_uninstall_ambassador(playbook,host_name,SRC_PACKAGE_PATH,ambassador_rbac):
    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"host_name\": \"'+host_name+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\",\"ambassador_rbac\": \"'+ambassador_rbac+'\"}\''
    logger.info(command)
    os.system(command)
    return True
def __launch_ansible_playbook_create_crd_network(playbook,ip,host_name,SRC_PACKAGE_PATH):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"ip\": \"'+ip+'\",\"host_name\": \"'+host_name+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_master_multus(playbook,ip,host_name,networking_plugin,SRC_PACKAGE_PATH):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"ip\": \"'+ip+'\",\"host_name\": \"'+host_name+'\",\"networking_plugin\": \"'+networking_plugin+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_scp_multus(playbook,ip,host_name,networking_plugin,SRC_PACKAGE_PATH):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"ip\": \"'+ip+'\",\"host_name\": \"'+host_name+'\",\"networking_plugin\": \"'+networking_plugin+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_node_multus(playbook,ip,host_name,networking_plugin,SRC_PACKAGE_PATH):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"ip\": \"'+ip+'\",\"host_name\": \"'+host_name+'\",\"networking_plugin\": \"'+networking_plugin+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_master_flannel(playbook,ip,host_name,networking_plugin,network,subnetLen,vni,SRC_PACKAGE_PATH):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"ip\": \"'+ip+'\",\"host_name\": \"'+host_name+'\",\"networking_plugin\": \"'+networking_plugin+'\",\"network\": \"'+network+'\",\"subnetLen\": \"'+subnetLen+'\",\"vni\": \"'+vni+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_node_flannel(playbook,ip,host_name,networking_plugin,network,subnetLen,vni,master_ip,SRC_PACKAGE_PATH):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"ip\": \"'+ip+'\",\"host_name\": \"'+host_name+'\",\"networking_plugin\": \"'+networking_plugin+'\",\"network\": \"'+network+'\",\"subnetLen\": \"'+subnetLen+'\",\"vni\": \"'+vni+'\",\"master_ip\": \"'+master_ip+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_create_flannel_networks(playbook,ip,host_name,networkName,vni,vniTemp,SRC_PACKAGE_PATH):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"ip\": \"'+ip+'\",\"host_name\": \"'+host_name+'\",\"networkName\": \"'+networkName+'\",\"vni\": \"'+vni+'\",\"vniTemp\": \"'+vniTemp+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_enable_sriov(playbook,host_name,intf,script,networking_plugin):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"sriov_intf\": \"'+intf+'\",\"host_name\": \"'+host_name+'\",\"script_path\": \"'+script+'\",\"networking_plugin\": \"'+networking_plugin+'\"}\''
    logger.info(command)
    os.system(command)
    return True
def __launch_ansible_playbook_build_sriov(playbook,SRC_PACKAGE_PATH,PROXY_DATA_FILE):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\",\"PROXY_DATA_FILE\": \"'+PROXY_DATA_FILE+'\"}\''
    logger.info(command)
    os.system(command)
    return True
def __launch_ansible_playbook_build_sriov_dpdk(playbook,SRC_PACKAGE_PATH,PROXY_DATA_FILE):
    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\",\"PROXY_DATA_FILE\": \"'+PROXY_DATA_FILE+'\"}\''
    logger.info(command)
    os.system(command)
    return True
def __launch_ansible_playbook_sriov_install(playbook,host_name,SRC_PACKAGE_PATH):
    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"host_name\": \"'+host_name+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\"}\''
    logger.info(command)
    os.system(command)
    return True
def __launch_ansible_playbook_sriov_dpdk_install(playbook,host_name,SRC_PACKAGE_PATH):
    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"host_name\": \"'+host_name+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\"}\''
    logger.info(command)
    os.system(command)
    return True
def __launch_ansible_playbook_dpdk_driver_load(playbook,host_name,dpdk_driver):
    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"host_name\": \"'+host_name+'\",\"dpdk_driver\": \"'+dpdk_driver+'\"}\''
    logger.info(command)
    os.system(command)
    return True
def __launch_ansible_playbook_sriov_dpdk_crd_nw(playbook,playbook_path_sriov_conf,sriov_intf,host_name,nw_name,dpdk_driver,dpdk_tool,node_hostname):
    print "node_hostname",node_hostname
    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"host_name\": \"'+host_name+'\",\"intf\": \"'+sriov_intf+'\",\"sriov_conf\": \"'+playbook_path_sriov_conf+'\",\"network_name\": \"'+nw_name+'\",\"dpdk_driver\": \"'+dpdk_driver+'\",\"dpdk_tool\": \"'+dpdk_tool+'\",\"node_hostname\": \"'+node_hostname+'\"}\''
    logger.info(command)
    os.system(command)
    return True
def __launch_ansible_playbook_sriov_dhcp_crd_nw(playbook,playbook_path_sriov_conf,sriov_intf,host_name,nw_name):
    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"host_name\": \"'+host_name+'\",\"intf\": \"'+sriov_intf+'\",\"sriov_conf\": \"'+playbook_path_sriov_conf+'\",\"network_name\": \"'+nw_name+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_sriov_crd_nw(playbook,playbook_path_sriov_conf,sriov_intf,host_name,nw_name,s_rng,e_rng,subnet,gw):
    print "kkkkkkkkkkk" 
    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"host_name\": \"'+host_name+'\",\"intf\": \"'+sriov_intf+'\",\"sriov_conf\": \"'+playbook_path_sriov_conf+'\",\"network_name\": \"'+nw_name+'\",\"rangeStart\": \"'+s_rng+'\",\"rangeEnd\": \"'+e_rng+'\",\"subnet\": \"'+subnet+'\",\"gateway\": \"'+gw+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_node_vlantag_interface(playbook,host,parentInterface,vlanId,ip):
    #command = "/usr/bin/ansible-playbook "+ playbook +" -e \"host="+host + " parentInterface="+parentInterface+ " vlanId="+vlanId +" ip="+ip+\"
#    command="docker run -d --ip=" +newip+ " --mac-address " +mac+ " --net="+macvlan+ " -ti "+container_image+" bash"
    command = "/usr/bin/ansible-playbook " +playbook + " -e " + "\"host="+host+" parentInterface="+parentInterface+ " vlanId="+str(vlanId) +" ip="+str(ip)+"\""
    logger.info(command)
    os.system(command)
    return True


def __launch_ansible_playbook_node_vlantag_interface_removal(playbook,host,parentInterface,vlanId):
    #command = "/usr/bin/ansible-playbook "+ playbook +" -e \"host="+host + " parentInterface="+parentInterface+ " vlanId="+vlanId +" ip="+ip+\"
#    command="docker run -d --ip=" +newip+ " --mac-address " +mac+ " --net="+macvlan+ " -ti "+container_image+" bash"
    command = "/usr/bin/ansible-playbook " +playbook + " -e " + "\"host="+host+" parentInterface="+parentInterface+ " vlanId="+str(vlanId) +"\""
    logger.info(command)
    os.system(command)
    return True
	

def __launch_ansible_playbook_network_creation(playbook,host,network_name,interface_node,subnet,rangeStart,rangeEnd,dst,gateway):
    #command = "/usr/bin/ansible-playbook "+ playbook +" -e \"host="+host + " parentInterface="+parentInterface+ " vlanId="+vlanId +" ip="+ip+\"
#    command="docker run -d --ip=" +newip+ " --mac-address " +mac+ " --net="+macvlan+ " -ti "+container_image+" bash"
    command = "/usr/bin/ansible-playbook " +playbook + " -e " + "\"host="+host+" network_name="+network_name+" interface_node="+interface_node+ " subnet="+subnet +" rangeStart="+rangeStart+" rangeEnd="+rangeEnd +" dst="+dst +" gateway="+gateway +"\""
    logger.info(command)
    os.system(command)
    return True


def __launch_ansible_playbook_network_removal(playbook,host,network_name):
    #command1 = "\"manoj\""
    #command = "/usr/bin/ansible-playbook "+ playbook +" -e \"host="+host + " parentInterface="+parentInterface+ " vlanId="+vlanId +" ip="+ip+\"
#    command="docker run -d --ip=" +newip+ " --mac-address " +mac+ " --net="+macvlan+ " -ti "+container_image+" bash"
    command = "/usr/bin/ansible-playbook " +playbook + " -e " + "\"host="+host+" network_name="+network_name+"\""
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_network_dhcp_creation(playbook,host,network_name,interface_node):
    #command = "/usr/bin/ansible-playbook "+ playbook +" -e \"host="+host + " parentInterface="+parentInterface+ " vlanId="+vlanId +" ip="+ip+\"
#    command="docker run -d --ip=" +newip+ " --mac-address " +mac+ " --net="+macvlan+ " -ti "+container_image+" bash"
    command = "/usr/bin/ansible-playbook " +playbook + " -e " + "\"host="+host+" network_name="+network_name+" interface_node="+interface_node+"\""
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook__dhcp_daemon_creation(playbook,host):
    #command = "/usr/bin/ansible-playbook "+ playbook +" -e \"host="+host + " parentInterface="+parentInterface+ " vlanId="+vlanId +" ip="+ip+\"
#    command="docker run -d --ip=" +newip+ " --mac-address " +mac+ " --net="+macvlan+ " -ti "+container_image+" bash"
    command = "/usr/bin/ansible-playbook " +playbook + " -e " + "\"host="+host+"\""
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook__dhcp_daemon_removal(playbook,host):
    #command = "/usr/bin/ansible-playbook "+ playbook +" -e \"host="+host + " parentInterface="+parentInterface+ " vlanId="+vlanId +" ip="+ip+\"
#    command="docker run -d --ip=" +newip+ " --mac-address " +mac+ " --net="+macvlan+ " -ti "+container_image+" bash"
    command = "/usr/bin/ansible-playbook " +playbook + " -e " + "\"host="+host+"\""
    logger.info(command)
    os.system(command)
    return True



def __launch_ansible_playbook_create_weave_network(playbook,ip,host_name,networkName,subnet,rangeStart,rangeEnd,dst,gateway,type_weave,SRC_PACKAGE_PATH):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"ip\": \"'+ip+'\",\"host_name\": \"'+host_name+'\",\"networkName\": \"'+networkName+'\",\"subnet\": \"'+subnet+'\",\"rangeStart\": \"'+rangeStart+'\",\"rangeEnd\": \"'+rangeEnd+'\",\"dst\": \"'+dst+'\",\"gateway\": \"'+gateway+'\",\"type_weave\": \"'+type_weave+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_delete_weave_conf(playbook,ip,host_name,networking_plugin,SRC_PACKAGE_PATH):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"ip\": \"'+ip+'\",\"host_name\": \"'+host_name+'\",\"networking_plugin\": \"'+networking_plugin+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_master_flannel_dynamic_node(playbook,ip,host_name,network,subnetLen,vni,SRC_PACKAGE_PATH):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"ip\": \"'+ip+'\",\"host_name\": \"'+host_name+'\",\"network\": \"'+network+'\",\"subnetLen\": \"'+subnetLen+'\",\"vni\": \"'+vni+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_dynamic_node_flannel(playbook,ip,host_name,network,subnetLen,vni,master_ip,SRC_PACKAGE_PATH):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"ip\": \"'+ip+'\",\"host_name\": \"'+host_name+'\",\"network\": \"'+network+'\",\"subnetLen\": \"'+subnetLen+'\",\"vni\": \"'+vni+'\",\"master_ip\": \"'+master_ip+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_scp_multus_dynamic_node(playbook,ip,host_name,master_ip,SRC_PACKAGE_PATH):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"ip\": \"'+ip+'\",\"host_name\": \"'+host_name+'\",\"master_ip\": \"'+master_ip+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_dynamic_node_multus(playbook,ip,host_name,networking_plugin,SRC_PACKAGE_PATH):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"ip\": \"'+ip+'\",\"host_name\": \"'+host_name+'\",\"networking_plugin\": \"'+networking_plugin+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_delete_conf_files(playbook,ip,host_name,networking_plugin,SRC_PACKAGE_PATH):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"ip\": \"'+ip+'\",\"host_name\": \"'+host_name+'\",\"networking_plugin\": \"'+networking_plugin+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\"}\''
    logger.info(command)
    os.system(command)
    return True
	
def __launch_ansible_playbook_metrics_server(playbook,ip,host_name,PROXY_DATA_FILE): #fucntion added by yashwant for metrics server

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"PROXY_DATA_FILE\": \"' + PROXY_DATA_FILE + '\",\"ip\": \"'+ip+'\",\"host_name\": \"'+host_name+'\"}\''
    logger.info(command)
    os.system(command)
    return True
	
def __launch_ansible_playbook_metrics_server_clean(playbook,ip,host_name): #fucntion added by yashwant for metrics server remove

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"ip\": \"'+ip+'\",\"host_name\": \"'+host_name+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_delete_flannel_interfaces(playbook,ip,host_name,node_type,networkName,SRC_PACKAGE_PATH):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"ip\": \"'+ip+'\",\"host_name\": \"'+host_name+'\",\"node_type\": \"'+node_type+'\",\"networkName\": \"'+networkName+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_create_default_network(playbook,ip,host_name,networkName,subnet,rangeStart,rangeEnd,dst,gateway,type_weave,networking_plugin,SRC_PACKAGE_PATH):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"ip\": \"'+ip+'\",\"host_name\": \"'+host_name+'\",\"networkName\": \"'+networkName+'\",\"subnet\": \"'+subnet+'\",\"rangeStart\": \"'+rangeStart+'\",\"rangeEnd\": \"'+rangeEnd+'\",\"dst\": \"'+dst+'\",\"gateway\": \"'+gateway+'\",\"type_weave\": \"'+type_weave+'\",\"networking_plugin\": \"'+networking_plugin+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_flannel_daemon(playbook,ip,host_name,subnet,SRC_PACKAGE_PATH):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"ip\": \"'+ip+'\",\"host_name\": \"'+host_name+'\",\"subnet\": \"'+subnet+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\"}\''
    logger.info(command)
    os.system(command)
    return True

def __launch_ansible_playbook_create_flannel_interface(playbook,ip,host_name,networkName,network,SRC_PACKAGE_PATH):

    command = '/usr/bin/ansible-playbook '+ playbook +' --extra-vars=\'{\"ip\": \"'+ip+'\",\"host_name\": \"'+host_name+'\",\"networkName\": \"'+networkName+'\",\"network\": \"'+network+'\",\"SRC_PACKAGE_PATH\": \"'+SRC_PACKAGE_PATH+'\"}\''
    logger.info(command)
    os.system(command)
    return True

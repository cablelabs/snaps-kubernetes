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
#This script is responsible for preparing all the files and variables neede for devstack deployment and calling the user defined  methods for the devstack  deployment
import re
import yaml
import shutil
import ansible_playbook_launcher
import os
import logging
import sys
import time
#Change the system path to import consts file
from common.consts import consts

DEFAULT_REPLACE_EXTENSIONS = None

logger = logging.getLogger('deploy_ansible_configuration')


"""****** start kubernetes fucntions *****************"""
#def launcher_configuration():
# """
# :add the proxy in apt_conf
# """
# PROXY_DATA_FILE=consts.PROXY_DATA_FILE
# VARIABLE_FILE=consts.VARIABLE_FILE
# playbook_path_proxy=consts.K8_LAUNCHER_PROXY
# logger.info('SET LAUNCHER PROXY')
# logger.info(playbook_path_proxy)
 #ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_uninstall_istio(playbook_path_proxy,PROXY_DATA_FILE)
# ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_proxy(playbook_path_proxy,PROXY_DATA_FILE,VARIABLE_FILE)
# if(ret_hosts!=True):
#    logger.info ('FAILED IN INSTALLING FILE PLAY')
#    exit(1)
# return ret_hosts
 
#def provision_preparation( proxy_dict, deployment_type,dpdk):
def provision_preparation( proxy_dict,dpdk):
 """
 This method is responsible for writing the hosts info in ansible hosts file proxy inf in ansible proxy file
 : param proxy_dict: proxy data in the dictionary format
 : return ret :
 """

 ## code which adds ip to the /etc/anisble/hosts file
 ret=True


 if proxy_dict:
   logger.debug("Adding proxies")
   proxy_file_in = open(consts.PROXY_DATA_FILE,"r+")
   proxy_file_in.seek(0)
   proxy_file_in.truncate()
   proxy_file_out = open(consts.PROXY_DATA_FILE,"w")
   proxy_file_out.write("---")
   proxy_file_out.write("\n")
   for key,value in proxy_dict.iteritems():
              logger.debug("Proxies added in file:"+key+":"+value)
              proxy_file_out.write(key+": "+str(value)+"\n")
   proxy_file_out.close()
   proxy_file_in.close()
   return ret

def clean_up_k8_addons(**k8_addon):#added by yashwant for addon clean up
    '''
    function to delete all addons : such as metrics server
    :param k8_addon:
    :return:
    '''
    return_stmt=False
    hostname_map=k8_addon.get("hostname_map")
    host_node_type_map = k8_addon.get("host_node_type_map")
    for addon in k8_addon:
        if addon=="metrics_server" and k8_addon.get("metrics_server")==True:
            return_stmt=clean_up_metrics_server(hostname_map, host_node_type_map)

    return return_stmt
def clean_up_k8(enable_istio,Git_branch,enable_ambassador,ambassador_rbac,Project_name):
 """
 This function is used for clean/Reset the  kubernet cluster
 """
 ret_host = False
 playbook_path_delete_project_folder_k8=consts.K8_REMOVE_FOLDER
 playbook_path_clean_k8=consts.K8_CLEAN_UP
 playbook_path_delete_nodes_k8=consts.K8_REMOVE_NODE_K8
 playbook_path_create_inventory=consts.KUBERNETES_CREATE_INVENTORY
 playbook_path_new_inventory_file=consts.KUBERNETES_NEW_INVENTORY
 SRC_PACKAGE_PATH=consts.INVENTORY_SOURCE_FOLDER
 HOST_FILE_PATH=consts.HOSTS_FILE
 ANSIBLE_HOST_FILE_PATH=consts.ANSIBLE_HOSTS_FILE
 playbook_path__uninstall_istio=consts.UNINSTALL_ISTIO
 playbook_path__uninstall_ambassador= consts.UNINSTALL_AMBASSADOR
 inventory_file_path=consts.K8_YAML+"inventory.cfg"
 VARIABLE_FILE=consts.VARIABLE_FILE
 PROXY_DATA_FILE=consts.PROXY_DATA_FILE
 master_hostname = get_host_master_name(Project_name) 
 host_name= master_hostname

 if(enable_istio=="yes"):
        ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_uninstall_istio(playbook_path__uninstall_istio,host_name,SRC_PACKAGE_PATH)
        if(ret_hosts!=True):
         logger.info ('FAILED IN INSTALLING FILE PLAY')
         exit(1)
#      else:
#        logger.info ('REMOVING TEMPRARY INVENTORY FILE')
#        os.remove(inventory_file_path)
 if(enable_ambassador=="yes"):
        ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_uninstall_ambassador(playbook_path__uninstall_ambassador,host_name,SRC_PACKAGE_PATH,ambassador_rbac)
        if(ret_hosts!=True):
         logger.info ('FAILED IN INSTALLING FILE PLAY')
         exit(1)
        

 logger.info('EXECUTING CLEAN K8 CLUSTER PLAY')
 logger.info(playbook_path_clean_k8)
 ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_clean_k8(playbook_path_clean_k8,SRC_PACKAGE_PATH,VARIABLE_FILE,PROXY_DATA_FILE,Git_branch,Project_name)
 if(ret_hosts!=True):
  logger.info ('FAILED IN CLEAN UP KUBERNETES CLUSTER ')
  exit(1)
 host_name_map_ip = get_hostname_ip_map_list(Project_name)
 for key,value in host_name_map_ip.iteritems():
     ip=value
     host_name=key
     logger.info('EXECUTING DELETE NODES PLAY')
     logger.info(playbook_path_delete_nodes_k8)
     ret_hosts=ansible_playbook_launcher.__launch_delete_host_k8(playbook_path_delete_nodes_k8,ip,host_name,HOST_FILE_PATH,ANSIBLE_HOST_FILE_PATH,VARIABLE_FILE,Project_name)
     if(ret_hosts!=True):
      logger.info ('FAILED IN DELTING NODE')
      exit(1)
 logger.info('EXECUTING REMOVE PROJECT FOLDER PLAY')
 logger.info(playbook_path_delete_project_folder_k8)
 ret_hosts=ansible_playbook_launcher.__launch_delete_project_folder(playbook_path_delete_project_folder_k8,VARIABLE_FILE,Project_name)
 if(ret_hosts!=True):
  logger.info ('FAILED IN CLEAN UP KUBERNETES CLUSTER ')
  exit(1)
 
 return ret_hosts

def clean_up_k8_nodes(host_name_list,dynamic_hostname_map,dynamic_host_node_type_map,Project_name):
 """
 This function is used for clean/Reset the specific node of kubernet cluster 
 : param host_name_list : list of all the host names
 """
 ret = False
 import os
 import re
 playbook_path_clean_k8_nodes=consts.K8_CLEAN_UP_NODES
 playbook_path_delete_node_k8=consts.K8_DELETE_NODE
 SRC_PACKAGE_PATH=consts.INVENTORY_SOURCE_FOLDER
 playbook_path_delete_nodes_k8=consts.K8_REMOVE_NODE_K8
 playbook_path_create_inventory=consts.KUBERNETES_CREATE_INVENTORY
 playbook_path_new_inventory_file=consts.KUBERNETES_NEW_INVENTORY
 HOST_FILE_PATH=consts.HOSTS_FILE
 ANSIBLE_HOST_FILE_PATH=consts.ANSIBLE_HOSTS_FILE
 VARIABLE_FILE=consts.VARIABLE_FILE
 PROXY_DATA_FILE=consts.PROXY_DATA_FILE
 master_hostname = get_host_master_name(Project_name) 
 
 for key,value in dynamic_hostname_map.iteritems():
     ip=value
     host_name=key
     logger.info('EXECUTING CLEAN K8 NODE PLAY')
     logger.info(playbook_path_clean_k8_nodes)
     ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_dynamic_k8_nodes_delete(playbook_path_clean_k8_nodes,host_name,SRC_PACKAGE_PATH,VARIABLE_FILE,PROXY_DATA_FILE,master_hostname,Project_name)
     if(ret_hosts!=True):
      logger.info ('FAILED IN DELTING NODE')
      exit(1)
     
     logger.info('EXECUTING REMOVE NODE FROM INVENTORY PLAY')
     logger.info(playbook_path_delete_node_k8)
     ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_delete_node(playbook_path_delete_node_k8,host_name,SRC_PACKAGE_PATH,VARIABLE_FILE,Project_name)
     if(ret_hosts!=True):
      logger.info ('FAILED IN DELTING NODE')
      exit(1)
     logger.info('EXECUTING REMOVE NODE FROM /etc/hosts and /etc/ansible/hosts PLAY')
     logger.info(playbook_path_delete_nodes_k8)
     ret_hosts=ansible_playbook_launcher.__launch_delete_host_k8(playbook_path_delete_nodes_k8,ip,host_name,HOST_FILE_PATH,ANSIBLE_HOST_FILE_PATH,VARIABLE_FILE,Project_name)
     if(ret_hosts!=True):
      logger.info ('FAILED IN DELTING NODE')
      exit(1)
 return ret_hosts

def deploy_k8_nodes(host_name_list,dynamic_hostname_map,dynamic_host_node_type_map,host_port_map,dynamic_hosts,Project_name,master_ip):
 """
 This function is used for deploy the specific node in  the kubernet cluster 
 : param host_name_list : list of all host name
 : param host_name_map : dictionary of all host name with ip map
 : param host_node_type_map : dictionary of all host name with node map
 """
 ret_host = False
 playbook_dynamic_conf_docker_repo=consts.K8_DYNAMIC_DOCKER_CONF
 playbook_path_node_labeling=consts.K8_NODE_LABELING
 playbook_path_deploy_k8_nodes=consts.K8_DEPLOY_NODES
 playbook_path_set_packages=consts.K8_SET_PACKAGES
 playbook_path_create_inventory=consts.KUBERNETES_CREATE_INVENTORY
 playbook_path_new_inventory_file=consts.KUBERNETES_NEW_INVENTORY
 PROXY_DATA_FILE=consts.PROXY_DATA_FILE
 VARIABLE_FILE=consts.VARIABLE_FILE
 SRC_PACKAGE_PATH=consts.INVENTORY_SOURCE_FOLDER
 APT_ARCHIVES_SRC=consts.APT_ARCHIVES_PATH
 CURRENT_DIR=consts.CWD
 master_hostname = get_host_master_name(Project_name) 
 
 for key,value in dynamic_hostname_map.iteritems():
     ip=value
     host_name=key
     registry_port=host_port_map.get(host_name)
     logger.info('EXECUTING CONFIGURE NODE PLAY')
     logger.info(playbook_path_set_packages)
     ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook(playbook_path_set_packages,ip,host_name,PROXY_DATA_FILE, VARIABLE_FILE,APT_ARCHIVES_SRC,SRC_PACKAGE_PATH,registry_port)
     if(ret_hosts!=True):
      logger.info ('FAILED IN DELTING NODE')
      exit(1)
     logger.info('EXECUTING CONFIGURE DOCKER REPO PLAY')
     logger.info(playbook_dynamic_conf_docker_repo)
     ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_dynamic_docker_conf(playbook_dynamic_conf_docker_repo,ip,host_name,master_ip,PROXY_DATA_FILE, VARIABLE_FILE)
     if(ret_hosts!=True):
      logger.info('FAILED IN CONFIGURE DOCKER REPO')
      exit(1)

 logger.info('EXECUTING DYNAMIC ADDITION OF NODE IN INVENTORY FILES PLAY')
 ret_hosts = modify_inventory_file(playbook_path_new_inventory_file,playbook_path_create_inventory,dynamic_hostname_map,dynamic_host_node_type_map,Project_name)
 if(ret_hosts!=True):
  logger.info('FAILED DYNAMIC ADDITION OF NODE IN INVENTORY FILES')
  exit(1)

 for i in range(len(host_name_list)):
     host_name=host_name_list[i]
     logger.info('EXECUTING SET HOSTS PLAY')
     logger.info(playbook_path_deploy_k8_nodes)
     ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_dynamic_k8_nodes(playbook_path_deploy_k8_nodes,host_name,SRC_PACKAGE_PATH,VARIABLE_FILE,PROXY_DATA_FILE,Project_name)
     if(ret_hosts!=True):
      logger.info ('FAILED IN DEPLOY NODE IN K8')
      exit(1)
 time.sleep( 5 );
##### Node labeling start ##########
 if dynamic_hosts:
  for i in range(len(dynamic_hosts)):
    label_key=dynamic_hosts[i].get(consts.HOST).get(consts.LABEL_KEY)
    hostname=dynamic_hosts[i].get(consts.HOST).get(consts.HOSTNAME)
    label_value=dynamic_hosts[i].get(consts.HOST).get(consts.LABEL_VALUE)
    logger.info ('EXECUTING LABEL NODE PLAY')
    logger.info(playbook_path_node_labeling)
    ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_node_labeling(playbook_path_node_labeling,master_hostname,hostname,label_key,label_value)
    if(ret_hosts!=True):
      logger.info ('FAILED IN LABEL NODE PLAY')
      exit(1)
      
##### Node labeling end ##########
 
 return ret_hosts

def launch_provisioning_kubernetes(host_name_map,host_node_type_map,host_port_map,service_subnet,pod_subnet,networking_plugin,enable_istio,docker_repo,hosts,Git_branch,enable_ambassador,ambassador_rbac,Project_name):
 """
 This function is used for deploy the kubernet cluster 
 """
 ret_host = False
 playbook_path_create_inventory_file=consts.K8_CREATE_INVENTORY_FILE
 playbook_path_node_labeling=consts.K8_NODE_LABELING
 playbook_path_set_packages=consts.K8_SET_PACKAGES
 playbook_conf_docker_repo=consts.K8_CONF_DOCKER_REPO
 playbook_private_docker_creation=consts.K8_PRIVATE_DOCKER
 playbook_path_set_launcher=consts.KUBERNETES_SET_LAUNCHER
 playbook_path_create_inventory=consts.KUBERNETES_CREATE_INVENTORY
 playbook_path_new_inventory_file=consts.KUBERNETES_NEW_INVENTORY
 playbook_path_weave_scope=consts.KUBERNETES_WEAVE_SCOPE
 playbook_path_setup_istio=consts.SETUP_ISTIO
 playbook_path_setup_ambassador=consts.SETUP_AMBASSADOR
 PROXY_DATA_FILE=consts.PROXY_DATA_FILE
 VARIABLE_FILE=consts.VARIABLE_FILE
 SRC_PACKAGE_PATH=consts.INVENTORY_SOURCE_FOLDER
 APT_ARCHIVES_SRC=consts.APT_ARCHIVES_PATH
 CURRENT_DIR=consts.CWD
 list_node=[]
 list_all=[]
 ip_control=None

 for key,value in host_node_type_map.iteritems():
     node_type=value
     if (node_type == "master"):
       master_hostname=key
 ####Node configuration start ####
 for key,value in host_name_map.iteritems():
     ip=value
     host_name=key
     registry_port=host_port_map.get(host_name)
     logger.info('EXECUTING SET HOSTS PLAY')
     logger.info(playbook_path_set_packages)
     ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook(playbook_path_set_packages,ip,host_name,PROXY_DATA_FILE, VARIABLE_FILE,APT_ARCHIVES_SRC,SRC_PACKAGE_PATH,registry_port)
     if(ret_hosts!=True):
      logger.info('FAILED SET HOSTS PLAY')
      exit(1)
 #####Node configuration end ########

 #####Docker Repository configuration start #######
 if (None != docker_repo):
     docker_ip= docker_repo.get(consts.IP)
     docker_port= docker_repo.get(consts.PORT)
     logger.info('EXECUTING CREATING PRIVATE DOCKER REPO PLAY')
     logger.info(playbook_private_docker_creation)
     ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_creating_docker_repo(playbook_private_docker_creation,PROXY_DATA_FILE, VARIABLE_FILE,docker_ip,docker_port,APT_ARCHIVES_SRC,SRC_PACKAGE_PATH)
     if(ret_hosts!=True):
       logger.info('FAILED IN  CREATING PRIVATE DOCKER REPO ')
       exit(1)
     for key,value in host_name_map.iteritems():
       ip=value
       host_name=key
       logger.info('EXECUTING CONFIGURE DOCKER REPO PLAY')
       logger.info(playbook_conf_docker_repo)
       ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_docker_conf(playbook_conf_docker_repo,ip,host_name,PROXY_DATA_FILE, VARIABLE_FILE,docker_ip,docker_port)
       if(ret_hosts!=True):
        logger.info('FAILED IN CONFIGURE DOCKER REPO')
        exit(1)
###### Docker Repository configuration end #########
 logger.info('CREATING INVENTORY FILE PLAY')
 logger.info(playbook_path_create_inventory_file)
 ret_hosts=ansible_playbook_launcher.__creating_inventory_file(playbook_path_create_inventory_file,SRC_PACKAGE_PATH,VARIABLE_FILE,CURRENT_DIR,Project_name)
 if(ret_hosts!=True):
     logger.info('CREATING INVENTORY FILE')
     exit(1)
 logger.info('EXECUTING MODIFIY INVENTORY FILES PLAY')
 logger.info(playbook_path_new_inventory_file)
 ret_hosts = modify_inventory_file(playbook_path_new_inventory_file,playbook_path_create_inventory,host_name_map,host_node_type_map,Project_name)
 if(ret_hosts!=True):
     logger.info('FAILED TO MODIFIY INVENTORY FILES')
     exit(1)
###### Launcher configuration start ########

 logger.info('EXECUTING SET HOSTS PLAY')
 logger.info(playbook_path_set_launcher)
 ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_k8(playbook_path_set_launcher,service_subnet,pod_subnet,networking_plugin,PROXY_DATA_FILE,VARIABLE_FILE,SRC_PACKAGE_PATH,CURRENT_DIR,Git_branch,Project_name) 
 if(ret_hosts!=True):
   logger.info ('FAILED IN SETTING LAUNCHER PACKAGES AND CONFIGURATION')
   exit(1)
##### Launcher configuration end ##########

##### Node labeling start ##########
 if hosts:
  for i in range(len(hosts)):
    label_key=hosts[i].get(consts.HOST).get(consts.LABEL_KEY)
    hostname=hosts[i].get(consts.HOST).get(consts.HOSTNAME)
    label_value=hosts[i].get(consts.HOST).get(consts.LABEL_VALUE)
    logger.info(playbook_path_node_labeling)
    ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_node_labeling(playbook_path_node_labeling,master_hostname,hostname,label_key,label_value)
    if(ret_hosts!=True):
      logger.info ('FAILED IN INSTALLING FILE PLAY')
      exit(1)
      
##### Node labeling end ##########
    #second_storage=ceph_hosts[i].get(consts.HOST).get(consts.STORAGE_TYPE)
        
 for key,value in host_node_type_map.iteritems():
     node_type=value
     host_name=key
     if (node_type == "master"):
#### Create Persistent Volume ########
     # for i in range(len(persistent_vol)):
      #  storage_size=persistent_vol[i].get(consts.CLAIM_PARAMETERS).get(consts.STORAGE)
       # claim_name=persistent_vol[i].get(consts.CLAIM_PARAMETERS).get(consts.CLAIM_NAME)
        #logger.info ('EXECUTING PERSISTENT VOLUME PLAY')
        #logger.info(playbook_path_persistent_volume)
     #	ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_persistent_volume(playbook_path_persistent_volume,host_name,SRC_PACKAGE_PATH,VARIABLE_FILE,storage_size,claim_name)
      #  if(ret_hosts!=True):
       #  logger.info ('FAILED IN INSTALLING FILE PLAY')
        # exit(1)
###### Weave scope installation  ########
       logger.info ('EXECUTING WEAVE SCOPE PLAY')
       logger.info(playbook_path_weave_scope)
       ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_weave_scope(playbook_path_weave_scope,host_name,SRC_PACKAGE_PATH,VARIABLE_FILE)
       if(ret_hosts!=True):
        logger.info ('FAILED IN INSTALLING FILE PLAY')
        exit(1)

 if enable_istio=="yes":
  logger.info('SETUP ISTIO')
  logger.info(playbook_path_setup_istio)
  inventory_file_path=consts.K8_INVENTORY+"inventory.cfg"
  ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_istio(playbook_path_setup_istio,inventory_file_path,PROXY_DATA_FILE)
  if(ret_hosts!=True):
    logger.info ('FAILED IN SETTING ISTIO')
    exit(1)
 if enable_ambassador=="yes":
  logger.info('SETUP AMBASSADOR')
  logger.info(playbook_path_setup_ambassador)
  inventory_file_path=consts.K8_INVENTORY+"inventory.cfg"
  ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_ambassador(playbook_path_setup_ambassador,inventory_file_path,PROXY_DATA_FILE,ambassador_rbac)
  if(ret_hosts!=True):
    logger.info ('FAILED IN SETTING AMBASSADOR')
    exit(1)
 return ret_hosts

def modify_user_list(user_name,user_password,user_id):
  VARIABLE_FILE=consts.VARIABLE_FILE
  SRC_PACKAGE_PATH=consts.INVENTORY_SOURCE_FOLDER
  logger.info('EXECUTING SET Authentication HOSTS PLAY')
  playbook_path_user_list=consts.KUBERNETES_USER_LIST
  logger.info(playbook_path_user_list)
  ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_update_user_list(playbook_path_user_list,user_name,user_password,user_id,SRC_PACKAGE_PATH)
  if(ret_hosts!=True):
        logger.info('FAILED SET HOSTS PLAY')
        exit(1)
  return ret_hosts
  
def update_kube_api_manifest_file(master_host_name):
  VARIABLE_FILE=consts.VARIABLE_FILE
  SRC_PACKAGE_PATH=consts.INVENTORY_SOURCE_FOLDER
  logger.info('EXECUTING SET Authentication HOSTS PLAY')
  playbook_path_authentication=consts.KUBERNETES_AUTHENTICATION
  logger.info(playbook_path_authentication)
  ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_authentication(playbook_path_authentication,master_host_name,SRC_PACKAGE_PATH,VARIABLE_FILE)
  if(ret_hosts!=True):
        logger.info('FAILED SET HOSTS PLAY')
        exit(1)
  return ret_hosts
"******************* etcd changes**************** "

def _modifying_etcd_node(master_host_name):
  VARIABLE_FILE=consts.VARIABLE_FILE
  SRC_PACKAGE_PATH=consts.INVENTORY_SOURCE_FOLDER
  logger.info('EXECUTING SET Authentication HOSTS PLAY')
  playbook_path_etcd_changes=consts.ETCD_CHANGES
  logger.info(playbook_path_etcd_changes)
  ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_etcd_changes(playbook_path_etcd_changes,master_host_name,SRC_PACKAGE_PATH,VARIABLE_FILE)
  if(ret_hosts!=True):
        logger.info('FAILED SET HOSTS PLAY')
        exit(1)
  return ret_hosts



"***************etcd changes end ********************"
def modify_inventory_file(playbook1,playbook2,host_name_map,host_node_type_map,Project_name):
 #playbook_path_new_inventory_file=consts.KUBERNETES_NEW_INVENTORY
 #playbook_path_create_inventory=consts.KUBERNETES_CREATE_INVENTORY
 VARIABLE_FILE=consts.VARIABLE_FILE
 SRC_PACKAGE_PATH=consts.INVENTORY_SOURCE_FOLDER
 CURRENT_DIR=consts.CWD
 for key,value in host_name_map.iteritems():
     ip=value
     host_name=key
     logger.info ('EXECUTING MODIFIED INVENTORY FILE PLAY')
     logger.info(playbook1)
     ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_new_inventory(playbook1,ip,host_name,SRC_PACKAGE_PATH,VARIABLE_FILE,CURRENT_DIR,Project_name)
     if(ret_hosts!=True):
      logger.info ('FAILED IN MODIFIED INVENTORY FILE PLAY')
      exit(1)

 for key,value in host_node_type_map.iteritems():
     node_type=value
     host_name=key
     logger.info ('EXECUTING MODIFIED INVENTORY FILE PLAY')
     logger.info(playbook2)
     ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_inventory(playbook2,node_type,host_name,SRC_PACKAGE_PATH,VARIABLE_FILE,Project_name)
     if(ret_hosts!=True):
      logger.info ('FAILED IN MODIFIED INVENTORY FILE PLAY')
      exit(1)
 return ret_hosts 

"""****** end kubernetes fucntions *****************"""

def launch_crd_network(host_name_map,host_node_type_map):
 """
 This function is used to create crd network 
 """
 ret_host = False
 playbook_path_create_crd_network=consts.K8_CREATE_CRD_NETWORK
 SRC_PACKAGE_PATH=consts.INVENTORY_SOURCE_FOLDER
 APT_ARCHIVES_SRC=consts.APT_ARCHIVES_PATH
 CURRENT_DIR=consts.CWD
 list_node=[]
 list_all=[]
 ip_control=None
# 
 for key,value in host_node_type_map.iteritems():
     node_type=value
     host_name=key
     logger.info ('EXECUTING CRD NETWORK CREATION PLAY')
     logger.info(playbook_path_create_crd_network)
     for key,value in host_name_map.iteritems():
        ip=value
        host_name1=key
        if (node_type == "master" and host_name1 == host_name):
           print ip
           print host_name
     	   ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_create_crd_network(playbook_path_create_crd_network,ip,host_name,SRC_PACKAGE_PATH)
           if(ret_hosts!=True):
             logger.info ('FAILED IN CREATING CRD NETWORK')
             exit(1)
 return ret_hosts

"""****** end kubernetes fucntions *****************"""

def launch_multus_cni(host_name_map,host_node_type_map,service_subnet,pod_subnet,networking_plugin,enable_istio):
 """
 This function is used to launch multus cni 
 """
 ret_host = False
 playbook_path_set_master_multus=consts.K8_MULTUS_SET_MASTER
 playbook_path_scp_multus=consts.K8_MULTUS_SCP_MULTUS_CNI
 playbook_path_set_node_multus=consts.K8_MULTUS_SET_NODE
 SRC_PACKAGE_PATH=consts.INVENTORY_SOURCE_FOLDER
 APT_ARCHIVES_SRC=consts.APT_ARCHIVES_PATH
 CURRENT_DIR=consts.CWD
 list_node=[]
 list_all=[]
 ip_control=None
 logger.info ('EXECUTING MULTUS CNI PLAY')
# 
 for key,value in host_node_type_map.iteritems():
     node_type=value
     host_name=key
     logger.info(playbook_path_set_master_multus)
     for key,value in host_name_map.iteritems():
        ip=value
        host_name1=key
        if (node_type == "master" and host_name1 == host_name):
           print ip
           print host_name
           logger.info ('EXECUTING MASTER MULTUS PLAY')
     	   ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_master_multus(playbook_path_set_master_multus,ip,host_name,networking_plugin,SRC_PACKAGE_PATH)
           if(ret_hosts!=True):
             logger.info ('FAILED IN INSTALLING MULTUS AT MASTER')
             exit(1)
        elif (node_type == "minion" and host_name1 == host_name):
           print ip
           print host_name
           logger.info ('EXECUTING SCP MULTUS PLAY')
     	   ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_scp_multus(playbook_path_scp_multus,ip,host_name,networking_plugin,SRC_PACKAGE_PATH)
           if(ret_hosts!=True):
             logger.info ('FAILED IN SCP MULTUS AT NODE')
             exit(1)
           logger.info ('EXECUTING NODE MULTUS PLAY')
     	   ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_node_multus(playbook_path_set_node_multus,ip,host_name,networking_plugin,SRC_PACKAGE_PATH)
           if(ret_hosts!=True):
             logger.info ('FAILED IN INSTALLING MULTUS AT NODE')
             exit(1)

 return ret_hosts

"""****** end kubernetes fucntions *****************"""    
def launch_flannel_interface(host_name_map,host_node_type_map,networking_plugin,item):
 """
 This function is used to launch flannel interface 
 """
 ret_host = False
 playbook_path_conf_flannel_intf_at_master=consts.K8_CONF_FLANNEL_INTERFACE_AT_MASTER
 playbook_path_conf_flannel_intf_at_node=consts.K8_CONF_FLANNEL_INTERFACE_AT_NODE
 SRC_PACKAGE_PATH=consts.INVENTORY_SOURCE_FOLDER
 APT_ARCHIVES_SRC=consts.APT_ARCHIVES_PATH
 CURRENT_DIR=consts.CWD
 list_node=[]
 list_all=[]
 ip_control=None
 logger.info ('EXECUTING FLANNEL INTERFACE CREATION PLAY')
# 
 networkDict=item.get("flannel_network")
 network = networkDict.get('network')
 subnetLen = networkDict.get('subnetLen')
 #subnetMax = item.get('subnetMax')
 #subnetMin = item.get('subnetMin')
 vni = networkDict.get('vni')

 for key,value in host_node_type_map.iteritems():
     node_type=value
     host_name=key
     logger.info(playbook_path_conf_flannel_intf_at_master)
     for key,value in host_name_map.iteritems():
        ip=value
        host_name1=key
        if (node_type == "master" and host_name1 == host_name):
           print ip
           print host_name
           master_ip = ip

           print network
           print subnetLen
           #print subnetMin
           #print subnetMax
           print vni
           print master_ip

           logger.info ('EXECUTING FLANNEL INTF PLAY AT MASTER')
     	   ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_master_flannel(playbook_path_conf_flannel_intf_at_master,ip,host_name,networking_plugin,network,subnetLen,vni,SRC_PACKAGE_PATH)
           if(ret_hosts!=True):
             logger.info ('FAILED IN CONFIGURING FLANNEL INTERFACE AT MASTER')
             exit(1)

 for key,value in host_node_type_map.iteritems():
     node_type=value
     host_name=key
     logger.info(playbook_path_conf_flannel_intf_at_master)
     for key,value in host_name_map.iteritems():
        ip=value
        host_name1=key
        if (node_type == "minion" and host_name1 == host_name):
           print ip
           print host_name

           print network
           print subnetLen
           #print subnetMin
          # print subnetMax
           print vni
           print master_ip

           logger.info ('EXECUTING FLANNEL INTF PLAY AT NODE')
     	   ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_node_flannel(playbook_path_conf_flannel_intf_at_node,ip,host_name,networking_plugin,network,subnetLen,vni,master_ip,SRC_PACKAGE_PATH)
           if(ret_hosts!=True):
             logger.info ('FAILED IN CONFIGURING FLANNEL INTERFACE AT NODE')
             exit(1)

 return ret_hosts
"""****** end kubernetes fucntions *****************"""

def create_flannel_networks(host_name_map,host_node_type_map,networking_plugin,item):
 """
 This function is used to create flannel networks
 """
 ret_host = False
 playbook_path_conf_flannel_network_creation=consts.K8_CONF_FLANNEL_NETWORK_CREATION
 SRC_PACKAGE_PATH=consts.INVENTORY_SOURCE_FOLDER
 APT_ARCHIVES_SRC=consts.APT_ARCHIVES_PATH
 CURRENT_DIR=consts.CWD
 list_node=[]
 list_all=[]
 ip_control=None
 logger.info ('CREATING FLANNEL NETWORK')
# 
 networkDict=item.get("flannel_network")
 networkName = networkDict.get('network_name')
 vni = networkDict.get('vni')
 print networkName
 print vni
 vniInt = int(vni)
 #if(vniInt > 1):
 vniTemp1 = (vniInt - 1)
 print vniTemp1
 vniTemp = str(vniTemp1)
 print vniTemp

 for key,value in host_node_type_map.iteritems():
     node_type=value
     host_name=key
     logger.info(playbook_path_conf_flannel_network_creation)
     for key,value in host_name_map.iteritems():
        ip=value
        host_name1=key
        if (node_type == "master" and host_name1 == host_name):
           print ip
           print host_name

           print networkName
           print vni
           print vniTemp1
           print vniTemp

           logger.info ('CREATING FLANNEL NETWORKS')
     	   ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_create_flannel_networks(playbook_path_conf_flannel_network_creation,ip,host_name,networkName,vni,vniTemp,SRC_PACKAGE_PATH)
           if(ret_hosts!=True):
             logger.info ('FAILED IN CONFIGURING FLANNEL INTERFACE AT MASTER')
             exit(1)
 return ret_hosts
"""****** end kubernetes fucntions *****************"""

##### #############################SR-IOV CNI INSTALLATION ########################################
def launch_sriov_cni_configuration(host_name_map,host_node_type_map,hosts_data_dict,Project_name):
 """
 This function is used to launch sriov cni 
 """
 ret_host = False
 playbook_path_sriov_build_cni=consts.K8_SRIOV_CNI_BUILD
 playbook_path_sriov_dpdk_cni=consts.K8_SRIOV_DPDK_CNI
 playbook_path_sriov_cni_enable=consts.K8_SRIOV_ENABLE
 playbook_path_sriov_cni_bin_inst=consts.K8_SRIOV_CNI_BIN_INST
 playbook_path_sriov_dpdk_cni_bin_inst=consts.K8_SRIOV_DPDK_CNI_BIN_INST
 playbook_path_cr_sriov_nw=consts.K8_SRIOV_CR_NW
 playbook_path_sriov_conf=consts.K8_SRIOV_CONF
 playbook_path_sriov_configuration_script=consts.K8_SRIOV_CONFIG_SCRIPT
 playbook_path_dpdk_driver_load=consts.K8_SRIOV_DPDK_DRIVER_LOAD
 PROXY_DATA_FILE=consts.PROXY_DATA_FILE
 SRC_PACKAGE_PATH=consts.K8_SOURCE_PATH
 APT_ARCHIVES_SRC=consts.APT_ARCHIVES_PATH
 CURRENT_DIR=consts.CWD
 minion_list=[]
 ip_control=None
 logger.info ('EXECUTING SRIOV CNI PLAY')
 print "INSIDE launch_sriov_cni"
 dpdk_enable = "no"
 
 import file_utils
 VARIABLE_FILE=consts.VARIABLE_FILE
 config=file_utils.read_yaml(VARIABLE_FILE)
 CURRENT_DIR=consts.CWD
 project_path=config.get(consts.PROJECT_PATH)
 inventory_file_path = project_path+Project_name+"/k8s-cluster.yml" 
 print inventory_file_path
 with open(inventory_file_path) as f:
  for line in f:
    if "kube_network_plugin:" in line:
       network_plugin1=line.split("kube_network_plugin:",1)[1]
       networking_plugin=network_plugin1.strip(' \t\n\r')
       hostnamestringlist = line.split(" ")
       networkPluginName=hostnamestringlist[0]
       networkPluginName=networkPluginName.strip(' \t\n\r')
       print "************network_plugin**********************"
       print networking_plugin

 for node in hosts_data_dict:
   for key in node:
        print node
        if ("Sriov" == key):
                allHosts= node.get("Sriov")
                print allHosts
                for hostData in allHosts:
                    print hostData
                    hostdetails=hostData.get("host")
                    hostname=hostdetails.get("hostname")
                    networks=hostdetails.get("networks")
                    print hostname
                    minion_list.append(hostname)
                    for network in networks:
                        #kernel_drive='igbvf'#network.get("kernel_driver")
                        dpdk_tool= '/etc/cni/scripts/dpdk-devbind.py'#network.get("dpdk_tool") 
                        dpdk_driver='vfio-pci'#network.get("dpdk_driver")
                        dpdk_enable=network.get("dpdk_enable")                        
                        rangeEnd=network.get("rangeEnd")
                        rangeStart=network.get("rangeStart")
                        sriov_gateway=network.get("sriov_gateway")
                        sriov_intf=network.get("sriov_intf")
                        sriov_subnet=network.get("sriov_subnet")
                        sriov_nw_name=network.get("network_name")
                        print "SRIOV CONFIGURATION ON NODES"
                        ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_enable_sriov(playbook_path_sriov_cni_enable,hostname,sriov_intf,playbook_path_sriov_configuration_script,networking_plugin)
  
 ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_build_sriov(playbook_path_sriov_build_cni,SRC_PACKAGE_PATH,PROXY_DATA_FILE) 
 print "dpdk flag ",dpdk_enable
 if(dpdk_enable == "yes"): 
     ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_build_sriov_dpdk(playbook_path_sriov_dpdk_cni,SRC_PACKAGE_PATH,PROXY_DATA_FILE)
 
 for  host_name in get_master_host_name_list(host_node_type_map):
     print "executing for master "+str(host_name)
     print "INSTALLING SRIOV BIN ON MASTER"
     ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_sriov_install(playbook_path_sriov_cni_bin_inst,host_name,SRC_PACKAGE_PATH)
     if(dpdk_enable == "yes"):
     	 print "INSTALLING SRIOV DPDK BIN ON MASTER"
         ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_sriov_dpdk_install(playbook_path_sriov_dpdk_cni_bin_inst,host_name,SRC_PACKAGE_PATH)
    

 for  host_name in minion_list:
     print "executing for  minion "+str(host_name)
     print "INSTALLING SRIOV BIN ON WORKERS"
     ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_sriov_install(playbook_path_sriov_cni_bin_inst,host_name,SRC_PACKAGE_PATH)
     if(dpdk_enable == "yes"):
     	 print "INSTALLING SRIOV DPDK BIN ON WORKERS"
         ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_dpdk_driver_load(playbook_path_dpdk_driver_load,host_name,dpdk_driver)
         ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_sriov_dpdk_install(playbook_path_sriov_dpdk_cni_bin_inst,host_name,SRC_PACKAGE_PATH)
 
 return ret_hosts


def launch_sriov_network_creation(host_name_map,host_node_type_map,hosts_data_dict,Project_name):
    ret_hosts = False
    playbook_path_cr_sriov_nw=consts.K8_SRIOV_CR_NW
    playbook_path_cr_sriov_dpdk_nw=consts.K8_SRIOV_DPDK_CR_NW
    playbook_path_cr_sriov_dhcp_nw=consts.K8_SRIOV_DHCP_CR_NW
    sriov_dhcp_daemon_playbook=consts.K8_DHCP_PATH
    playbook_path_sriov_conf=consts.K8_SRIOV_CONF
    master_list=get_master_host_name_list(host_node_type_map)
    print master_list
    #ret_host = validate_sriov_network_param(hosts_data_dict)
    #if(ret_host == True):
    #    print "duplicate nw name provided "
    #    return False
    masterHost = get_host_master_name(Project_name)
    #for masterHost in master_list:	
    print "*********doing config for node***********"+str(masterHost)
    for node in hosts_data_dict:
        for key in node:
            if ("Sriov" == key):
		allHosts= node.get("Sriov")
	        for hostData in allHosts:
	            hostdetails=hostData.get("host")
		    networks=hostdetails.get("networks")		                      
                    node_hostname=hostdetails.get("hostname")
		    for network in networks:
                        #kernel_drive= 'ixgbe'#network.get("kernel_driver")
                        #kernel_drive= get_kernal_driver() #'ixgbe'#network.get("kernel_driver")

                        dpdk_tool='/etc/cni/scripts/dpdk-devbind.py' 
                        dpdk_driver='vfio-pci'
                        dpdk_enable=network.get("dpdk_enable")                        
                        #rangeEnd=network.get("rangeEnd")
		        rangeEnd=network.get("rangeEnd")
		        rangeStart=network.get("rangeStart")
		        host=network.get("type")
		        sriov_gateway=network.get("sriov_gateway")
		        sriov_intf=network.get("sriov_intf")
		        sriov_subnet=network.get("sriov_subnet")
		        sriov_nw_name=network.get("network_name")
		        print masterHost
                        print "node_hostname",node_hostname
                        print "dpdk_driver:" ,dpdk_driver
                        print "dpdk_tool:",dpdk_tool
                    	#print "kernel_drive:",kernel_drive
                        print "dpdk_enable:",dpdk_enable
                        print "sriov_intf:",sriov_intf
                        print "masterHost:",masterHost
                        print "sriov_nw_name:",sriov_nw_name
                        print "rangeStart:",rangeStart
                        print "rangeEnd:",rangeEnd
                        print "sriov_subnet:",sriov_subnet
                        print "sriov_gateway :",sriov_gateway
                    	#print "kernel_drive:",kernel_drive
                        if(dpdk_enable == "yes"):
                            print "SRIOV NETWORK CREATION STARTED USING DPDK DRIVER"
	   	            ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_sriov_dpdk_crd_nw(playbook_path_cr_sriov_dpdk_nw,playbook_path_sriov_conf,sriov_intf,masterHost,sriov_nw_name,dpdk_driver,dpdk_tool,node_hostname)
                        if(dpdk_enable == "no"):
                            if(host == "host-local"):
                                print "SRIOV NETWORK CREATION STARTED USING KERNEL DRIVER WITH IPAM host-local"
	   	                ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_sriov_crd_nw(playbook_path_cr_sriov_nw,playbook_path_sriov_conf,sriov_intf,masterHost,sriov_nw_name,rangeStart,rangeEnd,sriov_subnet,sriov_gateway)
                        
                            if(host == "dhcp"):
                                print "SRIOV NETWORK CREATION STARTED USING KERNEL DRIVER WITH IPAM host-dhcp"
				ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_sriov_dhcp_crd_nw(playbook_path_cr_sriov_dhcp_nw,playbook_path_sriov_conf,sriov_intf,masterHost,sriov_nw_name)
                                #print "DHCP DAEMON RUNNING WITH SRIOV"
                                #ansible_playbook_launcher.__launch_ansible_playbook__dhcp_daemon_creation(sriov_dhcp_daemon_playbook,node_hostname)
                    
    return ret_hosts


def get_master_host_name_list(host_node_type_map):
        masterList=[]	
	print host_node_type_map
	for key,value in host_node_type_map.iteritems():	
		#print key
		#print value
		if value =="master":
			masterList.append(key)
        return masterList
        

"""****** end kubernetes fucntions *****************"""

def create_weave_interface(host_name_map,host_node_type_map,service_subnet,pod_subnet,networking_plugin,item):
 """
 This function is used to create weave interace and network
 """
 ret_host = False
 playbook_path_conf_weave_network_creation=consts.K8_CONF_WEAVE_NETWORK_CREATION
 playbook_path_conf_weave_conf_deletion=consts.K8_CONF_FILES_DELETION_AFTER_MULTUS
 SRC_PACKAGE_PATH=consts.INVENTORY_SOURCE_FOLDER
 APT_ARCHIVES_SRC=consts.APT_ARCHIVES_PATH
 CURRENT_DIR=consts.CWD
 list_node=[]
 list_all=[]
 ip_control=None
 logger.info ('CREATING WEAVE NETWORK')
# 
 networkDict=item.get("weave_network")
 networkName = networkDict.get('network_name')
 subnet = networkDict.get('subnet')
 rangeStart = networkDict.get('rangeStart')
 rangeEnd = networkDict.get('rangeEnd')
 dst = networkDict.get('dst')
 gateway = networkDict.get('gateway')
 type_weave = networkDict.get('type')
 print networkName
 print subnet
 print rangeStart
 print rangeEnd
 print dst
 print gateway

 for key,value in host_node_type_map.iteritems():
     node_type=value
     host_name=key
     logger.info(playbook_path_conf_weave_network_creation)
     for key,value in host_name_map.iteritems():
        ip=value
        host_name1=key
        if (node_type == "master" and host_name1 == host_name):
          print ip
          logger.info ('CREATING WEAVE NETWORKS')
          ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_create_weave_network(playbook_path_conf_weave_network_creation,ip,host_name,networkName,subnet,rangeStart,rangeEnd,dst,gateway,type_weave,SRC_PACKAGE_PATH)
          if(ret_hosts!=True):
            logger.info ('FAILED IN CONFIGURING WEAVE INTERFACE')
            exit(1)

 for key,value in host_node_type_map.iteritems():
     node_type=value
     host_name=key
     logger.info(playbook_path_conf_weave_conf_deletion)
     for key,value in host_name_map.iteritems():
        ip=value
        host_name1=key
        if (node_type == "minion" and host_name1 == host_name):
          print ip
#          print host_name
#          print networking_plugin
          logger.info ('DELETING CONF FILE')
          ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_delete_weave_conf(playbook_path_conf_weave_conf_deletion,ip,host_name,networking_plugin,SRC_PACKAGE_PATH)
          if(ret_hosts!=True):
            logger.info ('FAILED IN CONFIGURING WEAVE INTERFACE')
            exit(1)
 return ret_hosts
"""****** end kubernetes fucntions *****************"""

def __hostname_list(hosts):
  logger.info("Creating host name list")
  list=[]
  host_node_map={}
  for i in range(len(hosts)):
      host_name=""
      name=hosts[i].get(consts.HOST).get(consts.HOST_NAME)
      if name:
       host_name=name
       list.append(host_name)
  return list
  
  
def launch_metrics_server(hostname_map,host_node_type_map):#fucntion added by yashwant for metrics server
    return_stmnt=False
    logger.info("launch_metrics_server fucntion")
    playbook_path_metrics_server = consts.K8_METRRICS_SERVER
    PROXY_DATA_FILE = consts.PROXY_DATA_FILE
    for key, value in host_node_type_map.iteritems():
        node_type = value
        host_name = key
        if (node_type == "master" ):
            logger.info('CONFIGURING METRICS SERVER on --' + node_type + "---> " + host_name +" ip --> "+str(hostname_map[host_name]))
            return_stmnt=ansible_playbook_launcher.__launch_ansible_playbook_metrics_server(playbook_path_metrics_server,hostname_map[host_name],host_name,PROXY_DATA_FILE)

    return return_stmnt
def clean_up_metrics_server(hostname_map,host_node_type_map):#added by yashwant for metrics server clean up
    print "clean_up_metrics_server"
    return_stmnt = False
    for key, value in host_node_type_map.iteritems():
        node_type = value
        host_name = key
        if (node_type == "master" ):
            logger.info('REMOVING METRICS SERVER on --' + node_type + "---> " + host_name +" ip --> "+str(hostname_map[host_name]))
            return_stmnt=ansible_playbook_launcher.__launch_ansible_playbook_metrics_server_clean(consts.K8_METRRICS_SERVER_CLEAN,hostname_map[host_name], host_name)

    return return_stmnt
  
def launch_ceph_kubernetes(host_name_map,host_node_type_map,hosts,ceph_hosts):
 """
 This function is used for deploy the ceph 
 """
 ret_host = False
 playbook_path_ceph_volume=consts.KUBERNETES_CEPH_VOL
 playbook_path_ceph_storage=consts.KUBERNETES_CEPH_STORAGE
 playbook_path_ceph_volume2=consts.KUBERNETES_CEPH_VOL2
 playbook_path_ceph_volume_first=consts.KUBERNETES_CEPH_VOL_FIRST
 playbook_path_delete_secret=consts.KUBERNETES_CEPH_DELETE_SECRET
 playbook_path_ceph_deploy=consts.CEPH_DEPLOY
 playbook_path_ceph_mds=consts.CEPH_MDS
 playbook_path_ceph_deploy_admin=consts.CEPH_DEPLOY_ADMIN
 playbook_path_ceph_mon=consts.CEPH_MON
 PROXY_DATA_FILE=consts.PROXY_DATA_FILE
 VARIABLE_FILE=consts.VARIABLE_FILE
 SRC_PACKAGE_PATH=consts.INVENTORY_SOURCE_FOLDER
 CURRENT_DIR=consts.CWD
 list_node=[]
 list_all=[]
 for key,value in host_node_type_map.iteritems():
     node_type1=value
     if (node_type1 == "master"):
       master_hostname=key
 if hosts:
  for i in range(len(hosts)):
    logger.info(playbook_path_delete_secret)
    node_type=hosts[i].get(consts.HOST).get(consts.NODE_TYPE)
    logger.info(node_type)
    if (node_type == "master"):
      ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_delete_secret(playbook_path_delete_secret,master_hostname)
      if(ret_hosts!=True):
        logger.info ('FAILED IN INSTALLING FILE PLAY')
        exit(1)
 if ceph_hosts:
  ceph_hostnamelist = __hostname_list(ceph_hosts)
  for i in range(len(ceph_hosts)):
    host_ip=ceph_hosts[i].get(consts.HOST).get(consts.IP)
    host_name=ceph_hosts[i].get(consts.HOST).get(consts.HOSTNAME)
    node_type=ceph_hosts[i].get(consts.HOST).get(consts.NODE_TYPE)
    ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_ceph_volume_first(playbook_path_ceph_volume_first,host_name,SRC_PACKAGE_PATH,VARIABLE_FILE,PROXY_DATA_FILE,host_ip)
    if(ret_hosts!=True):
     logger.info ('FAILED IN INSTALLING FILE PLAY')
     exit(1)
    if (node_type=="ceph_controller"):
      ceph_controller_ip=ceph_hosts[i].get(consts.HOST).get(consts.IP)
      ceph_claims=ceph_hosts[i].get(consts.HOST).get(consts.CEPH_CLAIMS)
      logger.info ('EXECUTING CEPH VOLUME PLAY')
      logger.info(playbook_path_ceph_volume)
      controller_host_name=host_name
      for i in range(len(ceph_hostnamelist)):
          osd_host_name=ceph_hostnamelist[i]
          user_id=ceph_hosts[i].get(consts.HOST).get(consts.USER)
          passwd=ceph_hosts[i].get(consts.HOST).get(consts.PASSWORD)
          osd_ip=ceph_hosts[i].get(consts.HOST).get(consts.IP)
          ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_ceph_volume(playbook_path_ceph_volume,host_name,SRC_PACKAGE_PATH,VARIABLE_FILE,PROXY_DATA_FILE,osd_host_name,user_id, passwd,osd_ip)
      if(ret_hosts!=True):
        logger.info ('FAILED IN INSTALLING FILE PLAY')
        exit(1)
  for i in range(len(ceph_hostnamelist)):
      host_name=ceph_hostnamelist[i]
      user_id=ceph_hosts[i].get(consts.HOST).get(consts.USER)
      passwd=ceph_hosts[i].get(consts.HOST).get(consts.PASSWORD)
      logger.info(playbook_path_ceph_deploy)
      ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_ceph_deploy(playbook_path_ceph_deploy,host_name,controller_host_name,VARIABLE_FILE,PROXY_DATA_FILE,user_id, passwd)
      if(ret_hosts!=True):
        logger.info ('FAILED IN INSTALLING FILE PLAY')
        exit(1)
  logger.info(playbook_path_ceph_mon)
  ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_ceph_mon(playbook_path_ceph_mon,controller_host_name,VARIABLE_FILE,PROXY_DATA_FILE)
  if(ret_hosts!=True):
     logger.info ('FAILED IN INSTALLING FILE PLAY')
     exit(1)
  for i in range(len(ceph_hosts)):
    host_ip=ceph_hosts[i].get(consts.HOST).get(consts.IP)
    host_name=ceph_hosts[i].get(consts.HOST).get(consts.HOSTNAME)
    node_type=ceph_hosts[i].get(consts.HOST).get(consts.NODE_TYPE)
    flag_second_storage=0
    if (node_type=="ceph_osd"):
      flag_second_storage=1
      second_storage=ceph_hosts[i].get(consts.HOST).get(consts.STORAGE_TYPE)
      logger.info("secondstorage is")
      if (second_storage!=None):
       for i in range(len(second_storage)):
         storage=second_storage[i]
         logger.info ('EXECUTING CEPH STORAGE PLAY')
         logger.info(playbook_path_ceph_storage)
         ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_ceph_storage(playbook_path_ceph_storage,host_name,controller_host_name,SRC_PACKAGE_PATH,VARIABLE_FILE,storage,PROXY_DATA_FILE,node_type)
         if(ret_hosts!=True):
           logger.info ('FAILED IN INSTALLING FILE PLAY')
           exit(1)
  for i in range(len(ceph_hostnamelist)):
      host_name=ceph_hostnamelist[i]
      logger.info(playbook_path_ceph_deploy_admin)
      ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_ceph_deploy_admin(playbook_path_ceph_deploy_admin,host_name,controller_host_name,VARIABLE_FILE,PROXY_DATA_FILE)
      if(ret_hosts!=True):
        logger.info ('FAILED IN INSTALLING FILE PLAY')
        exit(1)
  logger.info(playbook_path_ceph_mds)
  ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_ceph_mon(playbook_path_ceph_mds,controller_host_name,VARIABLE_FILE,PROXY_DATA_FILE)
  if(ret_hosts!=True):
     logger.info ('FAILED IN INSTALLING FILE PLAY')
     exit(1)
 if hosts:
  for i in range(len(hosts)):
    node_type=hosts[i].get(consts.HOST).get(consts.NODE_TYPE)
    logger.info(node_type)
    if (node_type == "master"):
      hostname=hosts[i].get(consts.HOST).get(consts.HOSTNAME)
      logger.info(playbook_path_ceph_volume2)
      logger.info("flag secondstorage is")
      logger.info(flag_second_storage)
      if (1 == flag_second_storage):
        ceph_claims=ceph_hosts[i].get(consts.HOST).get(consts.CEPH_CLAIMS)
        for i in range(len(ceph_claims)):
          ceph_claim_name=ceph_claims[i].get(consts.CLAIM_PARAMETERS).get(consts.CEPH_CLAIM_NAME)
          print "**ceph_claim name**"
          print ceph_claim_name
          ceph_storage_size=ceph_claims[i].get(consts.CLAIM_PARAMETERS).get(consts.CEPH_STORAGE)
          print "**ceph_storage_size**"
          print ceph_storage_size
     	  ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_ceph_volume2(playbook_path_ceph_volume2,hostname,SRC_PACKAGE_PATH,VARIABLE_FILE,ceph_storage_size,ceph_claim_name,PROXY_DATA_FILE,controller_host_name,ceph_controller_ip)
          if(ret_hosts!=True):
            logger.info ('FAILED IN INSTALLING FILE PLAY')
            exit(1)
 return ret_hosts
def launch_persitent_volume_kubernetes(host_name_map,host_node_type_map,hosts,persistent_vol):
 """
 This function is used for deploy the persistent_volume 
 """
 ret_host = False
 playbook_path_persistent_volume=consts.KUBERNETES_PERSISTENT_VOL
 VARIABLE_FILE=consts.VARIABLE_FILE
 SRC_PACKAGE_PATH=consts.INVENTORY_SOURCE_FOLDER
 CURRENT_DIR=consts.CWD
 for key,value in host_node_type_map.iteritems():
     node_type=value
     host_name=key
     if (node_type == "master"):
      for i in range(len(persistent_vol)):
        storage_size=persistent_vol[i].get(consts.CLAIM_PARAMETERS).get(consts.STORAGE)
        claim_name=persistent_vol[i].get(consts.CLAIM_PARAMETERS).get(consts.CLAIM_NAME)
        logger.info ('EXECUTING PERSISTENT VOLUME PLAY')
        logger.info(playbook_path_persistent_volume)
     	ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_persistent_volume(playbook_path_persistent_volume,host_name,SRC_PACKAGE_PATH,VARIABLE_FILE,storage_size,claim_name)
        if(ret_hosts!=True):
         logger.info ('FAILED IN INSTALLING FILE PLAY')
         exit(1)
 return ret_hosts
 
#########get master host_name############ 
def get_host_master_name(Project_name):
 import file_utils
 VARIABLE_FILE=consts.VARIABLE_FILE
 config=file_utils.read_yaml(VARIABLE_FILE)
 project_path=config.get(consts.PROJECT_PATH)
 inventory_file_path = project_path+Project_name+"/inventory.cfg" 
 print "************Inventory file**********************"
 print inventory_file_path 
 with open(inventory_file_path) as f:
    for line in f:
        if re.match("\[kube\-master\]", line):
           master_hostname1=f.next()
           master_hostname=master_hostname1.strip(' \t\n\r')
           print "************master host name**********************"
           print master_hostname
 return master_hostname

def get_hostname_ip_map_list(Project_name):
 import file_utils
 VARIABLE_FILE=consts.VARIABLE_FILE
 config=file_utils.read_yaml(VARIABLE_FILE)
 project_path=config.get(consts.PROJECT_PATH)
 inventory_file_path = project_path+Project_name+"/inventory.cfg" 
 print "************Inventory file**********************"
 print inventory_file_path
 hostname_map={}
 with open(inventory_file_path) as f:
      for line in f:
        if "ansible_ssh_host=" in line:
           host_ip1=line.split("ansible_ssh_host=",1)[1]
           host_ip=host_ip1.strip(' \t\n\r')
	   hostnamestringlist = line.split(" ")
           host_name=hostnamestringlist[0]
           host_name=host_name.strip(' \t\n\r')
           if host_ip:
              if host_name:
                hostname_map[host_name]=host_ip
 print hostname_map 
 return hostname_map

def launch_multus_cni_dynamic_node(host_name_map,host_node_type_map,dynamic_hostname_map,dynamic_host_node_type_map,master_ip,Project_name):
 """
 This function is used to launch multus cni on dynamic node 
 """
 ret_host = False
 playbook_path_scp_multus_dynamic_code=consts.K8_MULTUS_SCP_MULTUS_CNI_DYNAMIC_NODE
 playbook_path_set_dynamic_node_multus=consts.K8_MULTUS_SET_DYNAMIC_NODE
 SRC_PACKAGE_PATH=consts.INVENTORY_SOURCE_FOLDER
 APT_ARCHIVES_SRC=consts.APT_ARCHIVES_PATH
 CURRENT_DIR=consts.CWD
 list_node=[]
 list_all=[]
 ip_control=None
 logger.info ('EXECUTING MULTUS CNI PLAY ON DYNAMIC NODE')
 import file_utils
 VARIABLE_FILE=consts.VARIABLE_FILE
 config=file_utils.read_yaml(VARIABLE_FILE)
 CURRENT_DIR=consts.CWD
 project_path=config.get(consts.PROJECT_PATH)
 inventory_file_path = project_path+Project_name+"/k8s-cluster.yml" 
 print inventory_file_path
 with open(inventory_file_path) as f:
      for line in f:
        if "kube_network_plugin:" in line:
           network_plugin1=line.split("kube_network_plugin:",1)[1]
           networking_plugin=network_plugin1.strip(' \t\n\r')
	   hostnamestringlist = line.split(" ")
           networkPluginName=hostnamestringlist[0]
           networkPluginName=networkPluginName.strip(' \t\n\r')
           print "************network_plugin**********************"
           print networking_plugin
# 

 for key,value in dynamic_hostname_map.iteritems():
     ip=value
     host_name=key
     print ip
     print host_name
     logger.info ('EXECUTING SCP MULTUS PLAY ON DYNAMIC NODE')
     ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_scp_multus_dynamic_node(playbook_path_scp_multus_dynamic_code,ip,host_name,master_ip,SRC_PACKAGE_PATH)
     if(ret_hosts!=True):
        logger.info ('FAILED IN SCP MULTUS AT NODE ON DYNAMIC NODE')
        exit(1)
     logger.info ('EXECUTING NODE MULTUS PLAY ON DYNAMIC NODE')
     ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_dynamic_node_multus(playbook_path_set_dynamic_node_multus,ip,host_name,networking_plugin,SRC_PACKAGE_PATH)
     if(ret_hosts!=True):
        logger.info ('FAILED IN INSTALLING MULTUS ON DYNAMIC NODE')
        exit(1)
 
 return ret_hosts
"""****** end kubernetes fucntions *****************"""    

def launch_flannel_interface_dynamic_node(dynamic_hostname_map,dynamic_host_node_type_map,item,master_ip,Project_name):
 """
 This function is used to launch flannel interface 
 """
 ret_host = False
 playbook_path_conf_flannel_intf_at_master_dynamic_node=consts.K8_CONF_FLANNEL_INTERFACE_AT_MASTER_FOR_DYNAMIC_NODE
 playbook_path_conf_flannel_intf_at_dynamic_node=consts.K8_CONF_FLANNEL_INTERFACE_AT_DYNAMIC_NODE
 SRC_PACKAGE_PATH=consts.INVENTORY_SOURCE_FOLDER
 APT_ARCHIVES_SRC=consts.APT_ARCHIVES_PATH
 CURRENT_DIR=consts.CWD
 list_node=[]
 list_all=[]
 ip_control=None
 master_hostname = get_host_master_name(Project_name)
 logger.info ('EXECUTING FLANNEL INTERFACE CREATION PLAY AT DYNAMIC NODE')
# 
 networkDict=item.get("flannel_network")
 network = networkDict.get('network')
 subnetLen = networkDict.get('subnetLen')
 #subnetMax = item.get('subnetMax')
 #subnetMin = item.get('subnetMin')
 vni = networkDict.get('vni')

 print master_ip
 print master_hostname
 print network
 print subnetLen
 #print subnetMin
 #print subnetMax
 print vni

 logger.info ('EXECUTING FLANNEL INTF PLAY AT MASTER_DYNAMIC_NODE')
 ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_master_flannel_dynamic_node(playbook_path_conf_flannel_intf_at_master_dynamic_node,master_ip,master_hostname,network,subnetLen,vni,SRC_PACKAGE_PATH)
 if(ret_hosts!=True):
   logger.info ('FAILED IN CONFIGURING FLANNEL INTERFACE AT MASTER FOR DYNAMIC NODE')
   exit(1)

 for key,value in dynamic_hostname_map.iteritems():
     ip=value
     host_name=key
     print ip
     print host_name
     print master_ip
     logger.info ('EXECUTING FLANNEL INTF PLAY AT DYNAMIC NODE')
     ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_dynamic_node_flannel(playbook_path_conf_flannel_intf_at_dynamic_node,ip,host_name,network,subnetLen,vni,master_ip,SRC_PACKAGE_PATH)
     if(ret_hosts!=True):
       logger.info ('FAILED IN CONFIGURING FLANNEL INTERFACE AT DYNAMIC NODE')
       exit(1)

 return ret_hosts
"""****** end kubernetes fucntions *****************"""
       
def delete_existing_conf_files(dynamic_hostname_map,dynamic_host_node_type_map,Project_name):
 """
 This function is used to delete existing conf files
 """
 ret_host = False
 playbook_path_conf_delete_existing_conf_files=consts.K8_CONF_FILES_DELETION_DYNAMIC_CODE
 SRC_PACKAGE_PATH=consts.INVENTORY_SOURCE_FOLDER
 APT_ARCHIVES_SRC=consts.APT_ARCHIVES_PATH
 CURRENT_DIR=consts.CWD
 list_node=[]
 list_all=[]
 ip_control=None
 logger.info ('DELETING EXISTING CONF FILES')
 import file_utils
 VARIABLE_FILE=consts.VARIABLE_FILE
 config=file_utils.read_yaml(VARIABLE_FILE)
 CURRENT_DIR=consts.CWD
 project_path=config.get(consts.PROJECT_PATH)
 inventory_file_path = project_path+Project_name+"/k8s-cluster.yml" 
 print inventory_file_path
 with open(inventory_file_path) as f:
      for line in f:
        if "kube_network_plugin:" in line:
           network_plugin1=line.split("kube_network_plugin:",1)[1]
           networking_plugin=network_plugin1.strip(' \t\n\r')
	   hostnamestringlist = line.split(" ")
           networkPluginName=hostnamestringlist[0]
           networkPluginName=networkPluginName.strip(' \t\n\r')
           print "************network_plugin**********************"
           print networking_plugin
# 
 for key,value in dynamic_hostname_map.iteritems():
     ip=value
     host_name=key
     print ip
     print host_name
     logger.info ('EXECUTING DELETE CONF FILES PLAY ON DYNAMIC NODE')
     ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_delete_conf_files(playbook_path_conf_delete_existing_conf_files,ip,host_name,networking_plugin,SRC_PACKAGE_PATH)
     if(ret_hosts!=True):
        logger.info ('FAILED IN DELETING CONF FILES ON DYNAMIC NODE')
        exit(1)
 
 return ret_hosts
"""****** end kubernetes fucntions *****************"""

def delete_existing_conf_files_after_additional_plugins(host_name_map,host_node_type_map,networking_plugin):
 """
 This function is used to delete existing conf files
 """
 ret_host = False
 playbook_path_conf_delete_existing_conf_files_after_multus=consts.K8_CONF_FILES_DELETION_AFTER_MULTUS
 SRC_PACKAGE_PATH=consts.INVENTORY_SOURCE_FOLDER
 APT_ARCHIVES_SRC=consts.APT_ARCHIVES_PATH
 CURRENT_DIR=consts.CWD
 list_node=[]
 list_all=[]
 ip_control=None
 logger.info ('DELETING EXISTING CONF FILES AFTER MULTUS')
# 
 for key,value in host_node_type_map.iteritems():
     node_type=value
     host_name=key
     logger.info(playbook_path_conf_delete_existing_conf_files_after_multus)
     for key,value in host_name_map.iteritems():
        ip=value
        host_name1=key
        if (node_type == "minion" and host_name1 == host_name):
           print ip
           print host_name
           logger.info ('EXECUTING DELETE CONF FILES PLAY')
           ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_delete_conf_files(playbook_path_conf_delete_existing_conf_files_after_multus,ip,host_name,networking_plugin,SRC_PACKAGE_PATH)
           if(ret_hosts!=True):
             logger.info ('FAILED IN DELETING CONF FILES')
             exit(1)

 return ret_hosts
"""****** end kubernetes fucntions *****************"""

def delete_flannel_interfaces(host_name_map,host_node_type_map,hosts_data_dict):
 """
 This function is used to launch flannel interfaces 
 """
 ret_host = False
 playbook_path_conf_delete_flannel_intf=consts.K8_DELETE_FLANNEL_INTERFACE
 SRC_PACKAGE_PATH=consts.INVENTORY_SOURCE_FOLDER
 APT_ARCHIVES_SRC=consts.APT_ARCHIVES_PATH
 CURRENT_DIR=consts.CWD
 list_node=[]
 list_all=[]
 ip_control=None
 logger.info ('EXECUTING FLANNEL INTERFACE DELETION PLAY')
# 
 i = 0
 for item1 in hosts_data_dict:
   for key in item1:
     if key == "Multus_network":
         multus_network=item1.get("Multus_network")
         for item2 in multus_network:
           for key in item2:
             if key == "CNI_Configuration":
               cni_configuration=item2.get("CNI_Configuration")
               for item3 in cni_configuration:
                 for key in item3:
                   if(consts.FLANNEL_NETWORK == key):
                     allHosts= item3.get(consts.FLANNEL_NETWORK)
	             for hostData in allHosts:
	               hostdetails=hostData.get("host")
	               host_name=hostdetails.get("hostname")
	               networks=hostdetails.get("flannel_networks")
                       if(i == 0): 
	                 networkName=hostdetails.get("network_name")		                      
                         #print "networkName :",networkName
                         i += 1 

 print "networkName :",networkName

 for key,value in host_node_type_map.iteritems():
     node_type=value
     host_name=key
     logger.info(playbook_path_conf_delete_flannel_intf)
     for key,value in host_name_map.iteritems():
        ip=value
        host_name1=key
        if (node_type == "master" and host_name1 == host_name):
         print ip
         print host_name1
         ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_delete_flannel_interfaces(playbook_path_conf_delete_flannel_intf,ip,host_name,node_type,networkName,SRC_PACKAGE_PATH)
         if(ret_hosts!=True):
           logger.info ('FAILED IN DELETING FLANNEL INTERFACE')
           exit(1)
        if (node_type == "minion" and host_name1 == host_name):
         print ip
         print host_name1
         ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_delete_flannel_interfaces(playbook_path_conf_delete_flannel_intf,ip,host_name,node_type,networkName,SRC_PACKAGE_PATH)
         if(ret_hosts!=True):
           logger.info ('FAILED IN DELETING FLANNEL INTERFACE')
           exit(1)

 return ret_hosts
"""****** end kubernetes fucntions *****************"""
                   
def create_default_network(host_name_map,host_node_type_map,service_subnet,pod_subnet,networking_plugin,item):
 """
 This function is create default network 
 """
 ret_host = False
 playbook_path_set_create_default_network=consts.K8_CREATE_DEFAULT_NETWORK
 SRC_PACKAGE_PATH=consts.INVENTORY_SOURCE_FOLDER
 APT_ARCHIVES_SRC=consts.APT_ARCHIVES_PATH
 CURRENT_DIR=consts.CWD
 list_node=[]
 list_all=[]
 ip_control=None
 logger.info ('EXECUTING CREATE DEFAULT NETWORK PLAY')

 subnet = item.get('pod_subnet')
 rangeStart = item.get('rangeStart')
 rangeEnd = item.get('rangeEnd')
 dst = item.get('dst')
 gateway = item.get('gateway')
 type_weave = item.get('type')
 networkName = item.get('network_name')
 print subnet
 print rangeStart
 print rangeEnd
 print dst
 print gateway
 print type_weave
 print networkName 

# 
 for key,value in host_node_type_map.iteritems():
     node_type=value
     host_name=key
     for key,value in host_name_map.iteritems():
       ip=value
       host_name1=key
       if (node_type == "master" and host_name1 == host_name):
          logger.info(playbook_path_set_create_default_network)
          ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_create_default_network(playbook_path_set_create_default_network,ip,host_name,networkName,subnet,rangeStart,rangeEnd,dst,gateway,type_weave,networking_plugin,SRC_PACKAGE_PATH)
          if(ret_hosts!=True):
             logger.info ('FAILED IN CREATING DEFAULT NETWORK')

 return ret_hosts
"""****** end kubernetes fucntions *****************"""

def create_flannel_interface(host_name_map,host_node_type_map,networking_plugin,Project_name,hosts_data_dict):
 ret_hosts = False
 playbook_path_conf_patch_node_master=consts.K8_CONF_FLANNEL_DAEMON_AT_MASTER
 playbook_path_conf_flannel_intf_at_master=consts.K8_CONF_FLANNEL_INTF_CREATION_AT_MASTER
 SRC_PACKAGE_PATH=consts.INVENTORY_SOURCE_FOLDER
 APT_ARCHIVES_SRC=consts.APT_ARCHIVES_PATH
 CURRENT_DIR=consts.CWD
 list_node=[]
 list_all=[]
 ip_control=None
 logger.info('EXECUTING FLANNEL INTERFACE CREATION PLAY IN CREATE FUNC')
 master_list=get_master_host_name_list(host_node_type_map)
 logger.info('*********master_list'+str(master_list))
 masterHost = get_host_master_name(Project_name)
 logger.info('*********doing config for node***********'+str(masterHost))

 for key,value in host_node_type_map.iteritems():
     node_type=value
     host_name=key
     for key,value in host_name_map.iteritems():
        ip=value
        host_name1=key
        if (node_type == "master" and host_name1 == host_name):
           logger.info('*******ip:'+ip)
           logger.info('*******host_name:'+host_name)
           master_ip = ip
           master_host_name = host_name
           logger.info('*******master_ip :'+master_ip)
           logger.info('*******master_host_name :'+master_host_name)

 for item1 in hosts_data_dict:
   for key in item1:
     if key == "Multus_network":
         multus_network=item1.get("Multus_network")
         for item2 in multus_network:
           for key in item2:
             if key == "CNI_Configuration":
               logger.info('*******CNI key:'+key)
               cni_configuration=item2.get("CNI_Configuration")
               for item3 in cni_configuration:
                 for key in item3:
                   logger.info('*******Network key:'+key)
                   if(consts.FLANNEL_NETWORK == key):
                     allHosts= item3.get(consts.FLANNEL_NETWORK)
	             for hostData in allHosts:
	               hostdetails=hostData.get("host")
	               host_name=hostdetails.get("hostname")
	               networks=hostdetails.get("flannel_networks")		                      
	               for network in networks:
	                 subnet=network.get("subnet")
	                 print masterHost
                         print "hostname :",host_name
                         print "subnet :",subnet
                         logger.info('*******Calling flannel daemon')
                         logger.info(playbook_path_conf_flannel_intf_at_master)
     	                 ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_flannel_daemon(playbook_path_conf_patch_node_master,master_ip,host_name,subnet,SRC_PACKAGE_PATH)
                         if(ret_hosts!=True):
                           ret_hosts = False
                           logger.info ('FAILED IN CREATING FLANNEL NETWORK')
                         else:
                           ret_hosts = True


 i = 0
 for item1 in hosts_data_dict:
   for key in item1:
     if key == "Multus_network":
         multus_network=item1.get("Multus_network")
         for item2 in multus_network:
           for key in item2:
             if key == "CNI_Configuration":
               cni_configuration=item2.get("CNI_Configuration")
               for item3 in cni_configuration:
                 for key in item3:
                   if(consts.FLANNEL_NETWORK == key):
                     allHosts= item3.get(consts.FLANNEL_NETWORK)
	             for hostData in allHosts:
	               hostdetails=hostData.get("host")
	               host_name=hostdetails.get("hostname")
	               networks=hostdetails.get("flannel_networks")
                       if(i == 0): 
	                 networkName=hostdetails.get("network_name")		                      
	                 network=hostdetails.get("network")		                      
                         #print "networkName :",networkName
                         i += 1 

 print "networkName :",networkName

 if(ret_hosts == True):
   ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_create_flannel_interface(playbook_path_conf_flannel_intf_at_master,master_ip,master_host_name,networkName,network,SRC_PACKAGE_PATH)
   if(ret_hosts!=True):
      ret_hosts = False
      logger.info ('FAILED IN CREATING FLANNEL NETWORK')

 return ret_hosts
"""****** end kubernetes fucntions *****************"""

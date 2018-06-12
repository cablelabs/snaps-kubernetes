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

'''import subprocess
import os
import sys
from common.utils import file_utils
import logging
import time,sys
import re
from common.consts import consts
import argparse
import logging
from optparse import OptionParser
sys.path.append("common/utils" )
from provision.kubernetes.deployment import deploy_infra
'''
from snaps_k8s.common.consts import consts
import logging
import string
logger = logging.getLogger('deploy_venv')

def validate_deployment_file(config):
  '''
  Calls all the validations
  '''
  logger.info("validate_deployment_file function")
  index = 1
  
  if validate_Kubernetes_tag(config)==False:
       exit(1)
   
  if validate_Kubernetes_params(config)==False:
       exit(1)

  if validate_api_ext_loadbalancer_tag_params(config)==True:
    if validate_countmasters(config)==False:
       exit(1)
    else:
       pass 
			       
  if validate_basic_authentication_tag(config)==False:
       exit(1)
  
  if validate_basic_authentication_params(config)==False:
       exit(1)
  
  if validate_node_config_tag(config)==False:
       exit(1)
  
  if validate_node_config_params(config)==False:
       exit(1)
  
  if validate_docker_repo_tag(config)==False:
       exit(1)
  
  if validate_docker_repo_params(config)==False:
       exit(1)
  
  if validate_proxies__tag(config)==False: 
       exit(1)
   
  if validate_proxy__params(config)==False:
       exit(1)
  
  if validate_network__tag(config)==False:
       exit(1)
  
  if validate_default_network__params(config)==False: 
       exit(1)
 
  if validate_multus_network_CNI(config,index)==False:
       exit(1)
  
  if validate_multus_network_cniConf(config,index)==False:
       exit(1)
  
  if validate_cni_params(config)==False:
       exit(1)
  
  if validate_duplicateinCNIandnetworkplugin(config)==False:
       exit(1)
  
  if validate_multus_network_CNIdhcp(config,index)==False:
       exit(1)
  
  if validate_multus_network_CNIconf__params(config)==False:
       exit(1)
  '''
  if validate_multus_network_falnnelnet__params(config)==False:
       exit(1)
  
  if validate_multus_network_Macvlan__params(config,index)==False:
       exit(1)
   
  if validate_multus_network_weave_params(config)==False:
       exit(1)
  
  if validate_multus_network_Sriov__params(config,index)==False:
       exit(1)
  '''
  if validate_dhcpmandatory(config,index)==False:
      exit(1)
  
  if validate_ceph_vol_tag(config)!=False:
       
       if validate_nodetype_data(config)==False:
            exit(1)
       
       if validate_ceph_vol_params(config)==False:
            exit(1)
  
       
       if validate_ceph_controller_params(config)==False:  
            exit(1)
       
       if validate_ceph_osd__params(config)==False:
            exit(1) 
       
  else:
       pass
  '''
  if validate_masterflag(config)==False:
       exit(1) 
  '''     
def validate_Kubernetes_tag(config):
   '''
   Checks the presence of Kubernetes tag
   '''
   logger.info("checking kubernetes tag")
   if validate_dict_data(config,consts.KUBERNETES)==False:
        return False 
  
def validate_Kubernetes_params(config):
    '''
    Checks the presence of Kubernetes parameters
    '''

    logger.info("checking kubernetes params")

    all_data_dictforkubernetesparams=config.get("kubernetes")
    if validate_dict_data(all_data_dictforkubernetesparams,consts.PROJECT_NAME)==False:
         return False
         exit(1)
    if validate_dict_data(all_data_dictforkubernetesparams,consts.GIT_BRANCH)==False:
         return False
         exit(1)
    if validate_dict_data(all_data_dictforkubernetesparams,consts.METRICS_SERVER)==False:
         return False
         exit(1)
    if validate_dict_data(all_data_dictforkubernetesparams,consts.HOSTS)==False:
         return False
         exit(1)
    if validate_dict_data(all_data_dictforkubernetesparams,consts.DOCKER_REPO)==False:
         return False
         exit(1)
    if validate_dict_data(all_data_dictforkubernetesparams,consts.NETWORKS)==False:
         return False
         exit(1)
    if validate_dict_data(all_data_dictforkubernetesparams,consts.PERSISTENT_VOLUME)==False:
         return False
         exit(1)
    if validate_dict_data2(all_data_dictforkubernetesparams,"Exclusive_CPU_alloc_support")==False:
         pass
    else:
         if all_data_dictforkubernetesparams['Exclusive_CPU_alloc_support']==True or all_data_dictforkubernetesparams['Exclusive_CPU_alloc_support']==False:
             pass
         else:
             return False     

def validate_api_ext_loadbalancer_tag_params(config):
     logger.info("checking api_ext_loadbalancer_tag")
     all_data_dictforkubernetesparams=config.get("kubernetes")
     all_data_dictForNodeConfigurationParams=config.get("kubernetes").get("node_configuration")
     all_data_dictforHA_params=config.get("kubernetes").get("ha_configuration")
     if validate_dict_data2(all_data_dictforkubernetesparams,"ha_configuration")==False:
         pass
     else:
         if validate_dict_data(all_data_dictforHA_params[0],"api_ext_loadbalancer"):
             if validate_dict_data(all_data_dictforHA_params[0].get("api_ext_loadbalancer"),"ip"):
                 if validate_dict_data(all_data_dictForNodeConfigurationParams[0],"host"):
                     for allDataForHost in all_data_dictForNodeConfigurationParams:
                         if allDataForHost.get("host")[consts.IP]==all_data_dictforHA_params[0].get("api_ext_loadbalancer")['ip']:
                             return False
             else:
                 return False
             if validate_dict_data(all_data_dictforHA_params[0].get("api_ext_loadbalancer"),"user"):
                 pass
             else:
                 return False
             if validate_dict_data(all_data_dictforHA_params[0].get("api_ext_loadbalancer"),"password"):
                 pass
             else:
                 return False
             if validate_dict_data(all_data_dictforHA_params[0].get("api_ext_loadbalancer"),"port"):
                 if all_data_dictforHA_params[0].get("api_ext_loadbalancer")['port']=="" or all_data_dictforHA_params[0].get("api_ext_loadbalancer")['port']==6443:
                      return False
             else:
                 return False
         else:
             return False 

def validate_countmasters(config):
     logger.info("checking Count the no of masters")
     count=0
     all_data_dictForNodeConfigurationParams=config.get("kubernetes").get("node_configuration")
     all_data_dictforKubernetesParams=config.get("kubernetes")
     if validate_dict_data(all_data_dictForNodeConfigurationParams[0],"host"):
          for allDataForHost in all_data_dictForNodeConfigurationParams:
               if allDataForHost.get("host")[consts.NODE_TYPE]=="master":
                    count=count+1
          if count%2==1 and count>1:
               return True
          return False
     
def validate_basic_authentication_tag(config):
     '''
     Checks the presence of basic_authentication tag
     '''
     logger.info("checking basic_authentication tag")

     all_data_dictforKubernetesParams=config.get("kubernetes")
     if validate_dict_data(all_data_dictforKubernetesParams,consts.BASIC_AUTHENTICATION)==False:
          return False
          exit(1)
     

def validate_basic_authentication_params(config):
     '''
     Checks the presence of basic_authentication parameters
     '''

     logger.info("checking basic_authentication params")

     all_data_dictforBasicauthenticationParams=config.get("kubernetes").get("basic_authentication")
     all_data_dictforKubernetesParams=config.get("kubernetes")
     if validate_dict_data(all_data_dictforBasicauthenticationParams[0],"user"):
          for allDataInAUser in all_data_dictforBasicauthenticationParams:
               if validate_dict_data(allDataInAUser.get("user"),"user_name")==False:
                    return False
                    exit(1)
               if validate_dict_data(allDataInAUser.get("user"),"user_password")==False:
                    return False
                    exit(1)

               if validate_dict_data(allDataInAUser.get("user"),"user_id")==False:
                    return False
                    exit(1)

     else:
           logger.error("USER is not present")
           return False
           exit(1)     
   
def validate_node_config_tag(config):
     '''
     Checks the presence of node configuration tag
     '''

     logger.info("checking node config tag")
     all_data_dictforKubernetesParams=config.get("kubernetes")
     if validate_dict_data(all_data_dictforKubernetesParams,consts.HOSTS)==False:
          return False
          exit(1) 
     

def validate_node_config_params(config):
     '''
     Checks the presence of node configuration parameters
     '''
     logger.info("checking node configuration params")

     all_data_dictForNodeConfigurationParams=config.get("kubernetes").get("node_configuration")
     all_data_dictforKubernetesParams=config.get("kubernetes")
     if validate_dict_data(all_data_dictForNodeConfigurationParams[0],"host"):
          for allDataForHost in all_data_dictForNodeConfigurationParams: 
               if validate_dict_data(allDataForHost.get("host"),consts.HOST_NAME)==False:
                    return False
                    exit(1)

               if validate_dict_data(allDataForHost.get("host"),consts.IP)==False:
                    return False
                    exit(1)
               if validate_dict_data(allDataForHost.get("host"),consts.NODE_TYPE)==False:
                    return False
                    exit(1)
               if validate_dict_data(allDataForHost.get("host"),consts.PASSWORD)==False:
                    return False
                    exit(1)
               if validate_dict_data(allDataForHost.get("host"),"user")==False:
                    return False
                    exit(1)   
     else:
          logger.error("host not present")
          return False
          exit(1)
   
def validate_docker_repo_tag(config): 
     '''
     Checks the presence of docker repo tag
     '''
     logger.info("checking docker repo tag")
     
     all_data_dictforKubernetesParams=config.get("kubernetes")
     if validate_dict_data(all_data_dictforKubernetesParams,consts.DOCKER_REPO)==False:
          return False
          exit(1)
   
         
        
def validate_docker_repo_params(config):
     '''
     Checks the presence of docker repo parameters
     '''
     logger.info("checking docker repo  params")
     all_data_dictforKubernetesParams=config.get("kubernetes")
     all_data_dictForDockerRepoParams=config.get("kubernetes").get("Docker_Repo")
     if validate_dict_data(all_data_dictForDockerRepoParams,consts.IP)==False:
          return False
          exit(1)
     if validate_dict_data(all_data_dictForDockerRepoParams,consts.PASSWORD)==False:
          return False
          exit(1)
     if validate_dict_data(all_data_dictForDockerRepoParams,"user")==False:
          return False
          exit(1)
     if validate_dict_data(all_data_dictForDockerRepoParams,consts.PORT)==False:
          return False
          exit(1)

    
def validate_proxies__tag(config):
     '''
     Checks the presence of proxies tag
     '''
     logger.info("checking proxies tag")

     all_data_dictforKubernetesParams=config.get("kubernetes")
     if validate_dict_data(all_data_dictforKubernetesParams,consts.PROXIES)==False:
          return False
          exit(1)
     

def validate_proxy__params(config):
     '''
     Checks the presence of proxy parameters
     '''
     logger.info("checking proxy  params")
     all_data_dictforKubernetesParams=config.get("kubernetes")
     all_data_dictForProxyParams=config.get("kubernetes").get("proxies")
     
     if validate_dict_data(all_data_dictForProxyParams,consts.HTTP_PROXY)==False:
          return False
          exit(1)
     if validate_dict_data(all_data_dictForProxyParams,consts.HTTPS_PROXY)==False:
          return False
          exit(1)

     if validate_dict_data(all_data_dictForProxyParams,consts.NO_PROXY)==False:
          return False
          exit(1)

        
def validate_network__tag(config):
     '''
     Checks the presence of network tag
     '''
     logger.info("checking networks tag")

     all_data_dictforKubernetesParams=config.get("kubernetes")
     if validate_dict_data(all_data_dictforKubernetesParams,consts.NETWORKS)==False: 
          return False
          exit(1)

     

def validate_default_network__params(config):
     '''
     Checks the presence of default network tag and its parameters
     '''
     logger.info("checking def networks  params")
     all_data_dictforKubernetesParams=config.get("kubernetes")
     all_data_dictForNetworkParams=config.get("kubernetes").get("Networks")
     if validate_dict_data(all_data_dictForNetworkParams[0],consts.DEFAULT_NETWORK)==True:
          if validate_dict_data(all_data_dictForNetworkParams[0].values()[0],consts.NETWORKING_PLUGIN)==False:
               return False;
               exit(1)
          else:
               if all_data_dictForNetworkParams[0].values()[0]['networking_plugin']!=None:
                   if validate_dict_data(all_data_dictForNetworkParams[0].values()[0],"isMaster"):
                        pass
                   else:
                        return False
          if validate_dict_data(all_data_dictForNetworkParams[0].values()[0],consts.SERVICE_SUBNET)==False:
               return False;
               exit(1)

          if validate_dict_data(all_data_dictForNetworkParams[0].values()[0],consts.POD_SUBNET)==False:
               return False;
               exit(1)

          if validate_dict_data(all_data_dictForNetworkParams[0].values()[0],consts.NETWORK_NAME)==False:
               return False;
               exit(1)

     else:
          logger.error("def network not present")
          return False
          exit(1)
        
def validate_multus_network_CNI(config,index):
     '''
     Checks the presence of CNI tag in Multus network and also checks presence of multus network tag
     '''
     logger.info("checking multus networks CNI ")
     all_data_dictforKubernetesParams=config.get("kubernetes")
     all_data_dictForNetworkParams=config.get("kubernetes").get("Networks")
     listForMultusNetworkParamsData =[]
     if validate_dict_data(all_data_dictForNetworkParams[index],"Multus_network")==True:
          listForMultusNetworkParamsData=all_data_dictForNetworkParams[index]['Multus_network']
          
          keytoAppendMultusNetworkParams=[]
          for element in listForMultusNetworkParamsData:


	       keytoAppendMultusNetworkParams.append(element.keys())
	  
          if ['CNI'] in keytoAppendMultusNetworkParams:
               return True
          else:
               logger.error("CNI does not exist")
               return False
               exit(1);
     else: 
          logger.error("Multus network does not exist")
          return False
          exit(1)

def validate_multus_network_cniConf(config,index):
     '''
     Checks the presence of CNI Configuration tag in Multus network and also checks presence of multus network tag
     '''

     logger.info("checking multus networks CNI CONF tag")
     all_data_dictforKubernetesParams=config.get("kubernetes")
     all_data_dictForNetworkParams=config.get("kubernetes").get("Networks")
     listForMultusNetworkParamsData =[]
     if validate_dict_data(all_data_dictForNetworkParams[index],"Multus_network")==True:
          listForMultusNetworkParamsData=all_data_dictForNetworkParams[index]['Multus_network']

          keytoAppendMultusNetworkParams=[]
          for element in listForMultusNetworkParamsData:


               keytoAppendMultusNetworkParams.append(element.keys())
          if ['CNI_Configuration'] in keytoAppendMultusNetworkParams:
               return True
          else:
               logger.error("CNIconfig does not exist")
               return False
               exit(1);
     

def validate_cni_params(config):
     '''
     Checks the presence of atleast one plugin in Cni tag
     '''
     index = 1
     logger.info("checking multus networks  params")
     all_data_dictforKubernetesParams=config.get("kubernetes")
     all_data_dictForNetworkParams=config.get("kubernetes").get("Networks")
     listForCNIparams=[]
     itemWeave=consts.WEAVE
     itemFlannel=consts.FLANNEL
     itemSriov="sriov"
     itemMacvlan="macvlan"
     itemdhcp="dhcp"
     for Allkeys in all_data_dictForNetworkParams[1]:
          for KeysInAllKeys in all_data_dictForNetworkParams[1][Allkeys]:
               listForCNIparams.append(KeysInAllKeys)
               break;
     if itemWeave in listForCNIparams[0].get("CNI"):
          if validate_masterflag(config)==False:
               return False
          else:
               pass

          if validate_multus_network_weave_params(config)==True: 
               pass
          else:
               return False

     if itemFlannel in listForCNIparams[0].get("CNI"):
          if validate_masterflag(config)==False:
               return False
          else:
               pass

          if validate_multus_network_falnnelnet__params(config)==True:
               pass
          else:
               return False

     if itemSriov in listForCNIparams[0].get("CNI"): 
          if validate_masterflag(config)==False:
               return False
          else:
               pass

          if validate_multus_network_Sriov__params(config,index)!=False:
               pass
          else:
               return False

     if itemMacvlan in listForCNIparams[0].get("CNI"):
          if validate_masterflag(config)==False:
               return False
          else:
               pass
          if validate_multus_network_Macvlan__params(config,index)!=False:
               pass
          else:
               return False
     if None in listForCNIparams[0].get("CNI") or itemdhcp in listForCNIparams[0].get("CNI"):
          if validate_masterflag(config)==False:
               return False
          else:
               pass

          pass
               

                    
def validate_duplicateinCNIandnetworkplugin(config):
     '''
     Checks if there exists the same plugin in both default network plugin tag and in  Cni parameters  
     '''

     logger.info("checking duplicate values")
     all_data_dictforKubernetesParams=config.get("kubernetes")
     all_data_dictForNetworkParams=config.get("kubernetes").get("Networks")
     networkpluginvalue=all_data_dictForNetworkParams[0].values()[0]['networking_plugin']
     
     listForCNIparams =[]
     itemWeave=consts.WEAVE
     itemFlannel=consts.FLANNEL
     itemSriov="sriov"
     itemMacvlan="macvlan"
     for Allkeys in all_data_dictForNetworkParams[1]:
          for KeysInAllKeys in all_data_dictForNetworkParams[1][Allkeys]:
               
               listForCNIparams.append(KeysInAllKeys)
               break;
     
          
     if itemWeave in listForCNIparams[0].get("CNI") and itemWeave==networkpluginvalue:
          logger.error("duplicate weave")
          return False
     if itemFlannel in listForCNIparams[0].get("CNI") and itemFlannel==networkpluginvalue:
          logger.error("duplicate flannel")
          return False 
     if itemSriov in listForCNIparams[0].get("CNI") and itemSriov==networkpluginvalue:
          logger.error("duplicate Sriov")
          return False
     if itemMacvlan in listForCNIparams[0].get("CNI") and itemMacvlan==networkpluginvalue:
          logger.error("duplicate macvlan")
          return False
        
def validate_multus_network_CNIdhcp(config,index):
     '''
     Checks the presence of dhcp if plugin is anyone of Sriov or Macvlan
     '''

     logger.info("checking cni dhcp params")
     all_data_dictforKubernetesParams=config.get("kubernetes")
     all_data_dictForNetworkParams=config.get("kubernetes").get("Networks")
     
     listForCNIparams =[]
     itemWeave=consts.WEAVE
     itemFlannel=consts.FLANNEL
     itemSriov="sriov"
     itemMacvlan="macvlan"
     itemdhcp="dhcp"
     for Allkeys in all_data_dictForNetworkParams[index]:
          for KeysInAllKeys in all_data_dictForNetworkParams[index][Allkeys]:

               listForCNIparams.append(KeysInAllKeys)
               break;

     if itemSriov in listForCNIparams[0].get("CNI") or  itemMacvlan in listForCNIparams[0].get("CNI"):
          if itemdhcp in KeysInAllKeys['CNI']:
               return True
               

          else:
               logger.error("dhcp must be defined when sriov or macvlan")
               return False
               exit(1)
     else:
          return False



def validate_multus_network_CNIconf__params(config):
     '''
     Checks the presence of all plugins in Cni Configuration parameters
     '''

     logger.info("checking cniconf  params")
     all_data_dictforKubernetesParams=config.get("kubernetes")
     all_data_dictForNetworkParams=config.get("kubernetes").get("Networks")

     listForCNI_Config_params =[]

     if True:   
          for Allkeys in all_data_dictForNetworkParams[1]:
               for KeysInAllKeys in all_data_dictForNetworkParams[1][Allkeys]:
                    CniConfigdata=KeysInAllKeys.get("CNI_Configuration")    
                    
               for element in CniConfigdata:
                     
                    listForCNI_Config_params.append(element.keys())    
               if ['Flannel'] in listForCNI_Config_params:
                    pass
                       
               else:
                    logger.error("flannel does not exist")
                    return False
                    exit(1);

               if ['Sriov'] in listForCNI_Config_params:
                    pass
                       
               else:
                    logger.error("Sriov does not exist")
                    return False
                    exit(1);
                   
               if ['Macvlan'] in listForCNI_Config_params:
                    pass
                       
               else:
                    logger.error("Macvlan does not exist")
                    return False
                    exit(1);
                  
               if ['Weave'] in listForCNI_Config_params:
                    pass
               else:
                    logger.error("Weave does not exist")
                    return False
                    exit(1);
     else:
          return False
          exit(1) 

def validate_multus_network_falnnelnet__params(config):
     '''
     Checks the presence of Flannel network parameters
     '''

     logger.info("checking falnnelnet params")
     all_data_dictforKubernetesParams=config.get("kubernetes")
     all_data_dictForNetworkParams=config.get("kubernetes").get("Networks")

     keysofallnetworks =[]
     value="Not found"
     if True:
          for Allkeys in all_data_dictForNetworkParams[1]:
               for KeysInAllKeys in all_data_dictForNetworkParams[1][Allkeys]:
                    CniConfigdata=KeysInAllKeys.get("CNI_Configuration")
                    
               for element in CniConfigdata:
                    
                    for Allkeys in element:
                         keysofallnetworks.extend(element.values()[0])
         
          for element in keysofallnetworks:
               if 'flannel_network' in element:
                    value="Found"          
                    if validate_dict_data(element['flannel_network'],"network_name")==True and validate_dict_data(element['flannel_network'],"network")==True and validate_dict_data(element['flannel_network'],"subnet")==True:
                         return True
                    else:
                         return False     
               
     if value == "Not found":
          return False
          exit(1)

def validate_multus_network_Macvlan__params(config,index):
     '''
     Checks the presence of Macvlan parameters also check Macvlan network name format and validations of "type"
     '''

     logger.info("checking Macvlan  params")
     all_data_dictforKubernetesParams=config.get("kubernetes")
     all_data_dictForNetworkParams=config.get("kubernetes").get("Networks")

     keysofallnetworks =[]
     value="Not found"
     if True:
          for Allkeys in all_data_dictForNetworkParams[index]:
               for KeysInAllKeys in all_data_dictForNetworkParams[index][Allkeys]:
                    CniConfigdata=KeysInAllKeys.get("CNI_Configuration")

               for element in CniConfigdata:

                    for Allkeys in element:
                         keysofallnetworks.extend(element.values()[0])
          
          for element in keysofallnetworks:
               
               if 'macvlan_networks' in element:
                    
                    if validate_dict_data(element['macvlan_networks'],"parent_interface")==True  and validate_dict_data(element['macvlan_networks'],"ip")==True and validate_dict_data(element['macvlan_networks'],"hostname")==True and validate_dict_data(element['macvlan_networks'],"vlanid")==True and validate_dict_data(element['macvlan_networks'],"master")==True  and validate_dict_data(element['macvlan_networks'],"type")==True and validate_dict_data(element['macvlan_networks'],"network_name")==True:
                         
                         stringfornwname=element['macvlan_networks']['network_name']
                         toFind = "_"
                         
                         count = 0
                         count2 = 0
                         count = stringfornwname.find(toFind)
                         count2=len(filter(lambda x: x in string.uppercase,stringfornwname))
                         
                         
                         if(count < 1 and count2< 1):
                             
                              pass
                         else:
                              logger.error("Network_name value format is wrong ")
                              return False
                         
                         if element['macvlan_networks']['type']=="host-local":
                              
                              if validate_dict_data(element['macvlan_networks'],"rangeEnd")==True and validate_dict_data(element['macvlan_networks'],"rangeStart")==True and validate_dict_data(element['macvlan_networks'],"routes_dst")==True and validate_dict_data(element['macvlan_networks'],"subnet")==True and validate_dict_data(element['macvlan_networks'],"gateway")==True:
                                   pass
                              else:
                                   return False
                    else: 
                         return False  
                    
def validate_multus_network_Sriov__params(config,index):
     '''
     Checks the presence of Macvlan parameters and validations of "type"
     '''
     logger.info("checking SRIOV  params")
     all_data_dictforKubernetesParams=config.get("kubernetes")
     all_data_dictForNetworkParams=config.get("kubernetes").get("Networks")

     keysofallnetworks =[]
     value="Not found"
     if True:
          for Allkeys in all_data_dictForNetworkParams[index]:
               for KeysInAllKeys in all_data_dictForNetworkParams[index][Allkeys]:
                    CniConfigdata=KeysInAllKeys.get("CNI_Configuration")

               for element in CniConfigdata:

                    for Allkeys in element:
                         keysofallnetworks.extend(element.values()[0])

          for element in keysofallnetworks:
               if 'host' in element:
                    value="Found"
                    if validate_dict_data(element['host'],"networks")==True  and validate_dict_data(element['host'],"hostname")==True:
                         
                         stringfornwname=element['host']['networks'][0]['network_name']
                         toFind = "_"

                         count = 0
                         count2 = 0
                         count = stringfornwname.find(toFind)
                         count2=len(filter(lambda x: x in string.uppercase,stringfornwname))


                         if(count < 1 and count2< 1):

                              pass
                         else:
                              logger.error("Network_name value format is wrong ")
                              return False

                         if validate_dict_data(element['host']['networks'][0],"type")==False:
                              return False
                              exit(1)
                         else:
                              if element['host']['networks'][0]['type']=="host-local":
                                  
                                   if validate_dict_data(element['host']['networks'][0],"rangeStart")==False:
                                        return False
                                   else: 
                                        return True
                                   if validate_dict_data(element['host']['networks'][0],"sriov_intf")==False:
                                        return False
                                   else:
                                        return True

                                   if validate_dict_data(element['host']['networks'][0],"rangeEnd")==False:
                                        return False
                                   else:
                                        return True 
                                   if validate_dict_data(element['host']['networks'][0],"network_name")==False:
                                        return False
                                   else:
                                        return True
                                   if validate_dict_data(element['host']['networks'][0],"dpdk_enable")==False:
                                        return False
                                   else:
                                        return True
                                   if validate_dict_data(element['host']['networks'][0],"sriov_gateway")==False:
                                        return False
                                   else:
                                        return True
                                   if validate_dict_data(element['host']['networks'][0],"sriov_subnet")==False:
                                        return False
                                   else:
                                        return True
                                   

                    else:
                         return False

     
 

def validate_multus_network_weave_params(config):
     '''
     Checks the presence of weave parameters
     '''
     logger.info("checking weave_params params")
     all_data_dictforKubernetesParams=config.get("kubernetes")
     all_data_dictForNetworkParams=config.get("kubernetes").get("Networks")

     keysofallnetworks =[]
     value="Not found"
     if True:
          for Allkeys in all_data_dictForNetworkParams[1]:
               for KeysInAllKeys in all_data_dictForNetworkParams[1][Allkeys]:
                    CniConfigdata=KeysInAllKeys.get("CNI_Configuration")

               for element in CniConfigdata:

                    for Allkeys in element:
                         keysofallnetworks.extend(element.values()[0])
          for element in keysofallnetworks:
               if 'weave_network' in element:
                    value="Found"
                    if validate_dict_data(element['weave_network'],"network_name")==True and validate_dict_data(element['weave_network'],"subnet")==True:
                         return True
                    else:
                         return False

     if value == "Not found":
          return False
          exit(1)

                    

def validate_ceph_vol_tag(config):
     '''
     Checks the presence of Ceph Volume tag
     '''
     logger.info("checking ceph_vol_tag")
     all_data_dictforKubernetesParams=config.get("kubernetes")
     all_data_dictForNetworkParams=config.get("kubernetes").get(consts.PERSISTENT_VOLUME)
     if validate_dict_data(all_data_dictForNetworkParams,"Ceph_Volume")==False:
          return False
          exit(1)
     if validate_dict_data(all_data_dictForNetworkParams,"Host_Volume")==False:
          return False
          exit(1)

def validate_ceph_vol_params(config):
     '''
     Checks the presence of Ceph Volume parameters
     '''
     logger.info("checking ceph_vol_params")
     
     all_data_dictForCephVloumeparam=config.get("kubernetes").get(consts.PERSISTENT_VOLUME).get("Ceph_Volume")
   
     for allCephVolumeparamData in all_data_dictForCephVloumeparam:
          if validate_dict_data(allCephVolumeparamData.get("host"),consts.HOST_NAME)==False:
               return False
               exit(1)
          if validate_dict_data(allCephVolumeparamData.get("host"),consts.IP)==False:
               return False
               exit(1)

          if validate_dict_data(allCephVolumeparamData.get("host"),consts.NODE_TYPE)==False:
               return False
               exit(1)

          if validate_dict_data(allCephVolumeparamData.get("host"),consts.PASSWORD)==False:
               return False
               exit(1)

          if validate_dict_data(allCephVolumeparamData.get("host"),"user")==False:
               return False
               exit(1)
             

def validate_nodetype_data(config):
     '''
     Checks the presence of nodetype datatype
     '''

     logger.info("checking nodetype_data")

     all_data_dictForCephVloumeparam=config.get("kubernetes").get(consts.PERSISTENT_VOLUME).get("Ceph_Volume")
     
     for allCephVolumeparamData in all_data_dictForCephVloumeparam:
          if validate_dict_data(allCephVolumeparamData.get("host"),consts.NODE_TYPE)==True:
               if allCephVolumeparamData.get("host")['node_type']== "ceph_controller" or allCephVolumeparamData.get("host")['node_type']== "ceph_osd":
                    return True
               else:
                    logger.error("ceph_controller or ceph_osd both are not present in node_type")
                    return False
                    exit(1)
          else: 
               return False
               exit(1)

def validate_ceph_claim_params(config):
     '''
     Checks the presence of Ceph Claim tag and its parameters
     '''

     logger.info("checking ceph_claim_params")
     all_data_dictForCephVloumeparam=config.get("kubernetes").get(consts.PERSISTENT_VOLUME).get("Ceph_Volume")
     
     for allCephVolumeparamData in all_data_dictForCephVloumeparam:
          if consts.CEPH_CLAIMS in allCephVolumeparamData.get("host"):
              
               for element in allCephVolumeparamData.get("host").get("Ceph_claims"):
                    dictClaimparam=element['claim_parameters']
                    
                    if validate_dict_data(dictClaimparam,"claim_name")==False:
                         return False
                         exit(1)
                    if validate_dict_data(dictClaimparam,"storage")==False:
                         return False
                         exit(1)
          else:  
               return False
               exit(1)

def validate_ceph_controller_params(config):
     '''
     Checks the presence of Ceph Controller parameters for ceph claim
     '''

     logger.info("checking ceph_controller_params")
     all_data_dictForCephVloumeparam=config.get("kubernetes").get(consts.PERSISTENT_VOLUME).get("Ceph_Volume")
     
     for allCephVolumeparamData  in all_data_dictForCephVloumeparam:
          if allCephVolumeparamData.get("host")['node_type']== "ceph_controller":
               if consts.CEPH_CLAIMS in allCephVolumeparamData.get("host") and "second_storage" not in allCephVolumeparamData.get("host"):
                    
                    return True
               else:
                    logger.error("for ceph_controller only CephClaim should be present")
                    return False
                    exit(1)
          
     
def validate_ceph_osd__params(config):
     '''
     Checks the presence of Ceph osd parameters foe secondary storage presence
     '''

     logger.info("checking ceph_osd_params")
     all_data_dictForCephVloumeparam=config.get("kubernetes").get(consts.PERSISTENT_VOLUME).get("Ceph_Volume")
     
     
     for allCephVolumeparamData  in all_data_dictForCephVloumeparam:
          
          
          if allCephVolumeparamData.get("host")['node_type']== "ceph_osd":
               
               if consts.CEPH_CLAIMS not in allCephVolumeparamData.get("host") and "second_storage" in allCephVolumeparamData.get("host"):
                    
                    return True
               else:
                    logger.error("for ceph_osd only secondary storage should be present")
                    return False
                    exit(1)
          


        

def validate_dhcpmandatory(config,index):
     '''
     Checks the presence of dhcp mandatory in Cni plugin if dhcp  present in any plugin type
     '''

     logger.info("checking dhcp mandatory values")
     all_data_dictforKubernetesParams=config.get("kubernetes")
     all_data_dictForNetworkParams=config.get("kubernetes").get("Networks")

     
     liForCNIparams =[]
     itemdhcp="dhcp"
     for Allkeys in all_data_dictForNetworkParams[index]:
          for KeysInAllKeys in all_data_dictForNetworkParams[index][Allkeys]:
               
               liForCNIparams.append(KeysInAllKeys)
               break;
     count = 0
     if itemdhcp in liForCNIparams[0].get("CNI"):
          count=count+1
          
     liForCNI_Confparams =[]
     value="Not found"
     if True:
          for Allkeys in all_data_dictForNetworkParams[index]:
               for KeysInAllKeys in all_data_dictForNetworkParams[index][Allkeys]:
                    datainCNI_Conf=KeysInAllKeys.get("CNI_Configuration")
                    
               for element in datainCNI_Conf:
                    
                    for Allkeys in element:

                         liForCNI_Confparams.extend(element.values()[0])
          
          for element in liForCNI_Confparams:
               if 'host' in element:
                    value="Found"
                    if validate_dict_data(element['host'],"networks")==True  and validate_dict_data(element['host'],"hostname")==True:
                         
                         if element['host']['networks'][0]['type']=="dhcp": 
                              if count>0:
                                   pass     
                              else:
                                   return False
     listforCNI_Conf2 =[]
     value="Not found"
     if True:
          for Allkeys in all_data_dictForNetworkParams[index]:
               for KeysInAllKeys in all_data_dictForNetworkParams[index][Allkeys]:
                    datainCNI_Conf=KeysInAllKeys.get("CNI_Configuration")
                    
                    
               for element in datainCNI_Conf:
                   listforCNI_Conf2.extend(element.values()[0])
          for element in listforCNI_Conf2:
              
               if 'macvlan_networks' in element:
                  
                    if element['macvlan_networks']['type']=="dhcp":
                         if count>0:
                              pass
                         else:
                              return False
def validate_masterflag(config):
     '''
     Checks the presence of master fag must be true for only once
     '''

     logger.info("checking Master Flag params")
     all_data_dictforKubernetesParams=config.get("kubernetes")
     all_data_dictForNetworkParams=config.get("kubernetes").get("Networks")
     listForCNI_Confparams =[]
     count=0
     isMasterval=all_data_dictForNetworkParams[0].values()[0]["isMaster"]
     
     if isMasterval=="true":
          count=count+1
          
     if True:
          for Allkeys in all_data_dictForNetworkParams[1]:
               for KeysInAllKeys in all_data_dictForNetworkParams[1][Allkeys]:
                    datainCNI_Conf=KeysInAllKeys.get("CNI_Configuration")


               for element in datainCNI_Conf:
                   listForCNI_Confparams.extend(element.values()[0])


          for element in listForCNI_Confparams:
               
               if 'macvlan_networks' in element:
                    isMastervalforMacvlan=element['macvlan_networks']['isMaster']
                    if isMastervalforMacvlan=="True":
                         count=count+1
               if 'weave_network' in element:
                    isMastervalforweave=element['weave_network']['isMaster']
                    if isMastervalforweave=="True":
                         count=count+1
               if 'flannel_network' in element:
                    isMastervalforflannel=element['flannel_network']['isMaster']
                    if isMastervalforflannel=="True":
                         count=count+1
               
               if 'host' in element:
                    isMasterforSriov=element['host']['networks'][0]['isMaster'] 
                    if isMasterforSriov=="True":
                         count=count+1
     if count!=1:
          logger.info("isMaster is true more than 1 time")
          return False
     else:
          pass

def validate_dict_data(dictName,dictItem):
     if dictName.get(dictItem):
          return True
     else:
          logger.error(dictItem + " item not exists !! validation failed")
          return False
          

def validate_dict_data2(dictName,dictItem):
     if dictName.get(dictItem):
          return True
     else:
          
          return False
          

#################################Dynamic Deployment Validation Start############################################

################Function validate cni params for dynamic deployment Start##########################
def validate_cni_params_for_dynamic_deployment(config):
     '''
     Checks the presence of atleast one plugin in Cni tag
     '''
     index = 0
     logger.info("checking multus networks params for dynamic deployment")
     all_data_dictforKubernetesParams=config.get("kubernetes")
     all_data_dictForNetworkParams=config.get("kubernetes").get("Networks")
     listForCNIparams=[]
     itemSriov="sriov"
     itemMacvlan="macvlan"
     itemdhcp="dhcp"
     for Allkeys in all_data_dictForNetworkParams[0]:
          for KeysInAllKeys in all_data_dictForNetworkParams[0][Allkeys]:
               listForCNIparams.append(KeysInAllKeys)
               break;

     if itemSriov in listForCNIparams[0].get("CNI"): 
          if validate_masterflag_dynamic_dep(config)==False:
               return False
          else:
               pass

          if validate_multus_network_Sriov__params(config,index)!=False:
               pass
          else:
               return False

     if itemMacvlan in listForCNIparams[0].get("CNI"):
          if validate_masterflag_dynamic_dep(config)==False:
               return False
          else:
               pass
          if validate_multus_network_Macvlan__params(config,index)!=False:
               pass
          else:
               return False

     if None in listForCNIparams[0].get("CNI") or itemdhcp in listForCNIparams[0].get("CNI"):
          if validate_masterflag_dynamic_dep(config)==False:
               return False
          else:
               pass

          pass
################Function validate cni params for dynamic deployment End##########################
               

################Function validate multus network CNIconf params for dynamic deployment Start##########################
def validate_multus_network_CNIconf__params_for_dynamic_deployment(config):
     '''
     Checks the presence of all plugins in Cni Configuration parameters
     '''

     logger.info("checking cniconf params for dynamic deployment")
     all_data_dictforKubernetesParams=config.get("kubernetes")
     all_data_dictForNetworkParams=config.get("kubernetes").get("Networks")

     listForCNI_Config_params =[]

     if True:   
          for Allkeys in all_data_dictForNetworkParams[0]:
               for KeysInAllKeys in all_data_dictForNetworkParams[0][Allkeys]:
                    CniConfigdata=KeysInAllKeys.get("CNI_Configuration")    
                    
               for element in CniConfigdata:
                     
                    listForCNI_Config_params.append(element.keys())    

               if ['Sriov'] in listForCNI_Config_params:
                    pass
                       
               else:
                    logger.error("Sriov does not exist")
                    return False
                    exit(1);
                   
               if ['Macvlan'] in listForCNI_Config_params:
                    pass
                       
               else:
                    logger.error("Macvlan does not exist")
                    return False
                    exit(1);
                  
     else:
          return False
          exit(1) 
################Function validate multus network CNIconf params for dynamic deployment End##########################

################Function validate isMaster for dynamic dep and dep file Start##########################
def validate_isMaster_for_dynamic_dep_and_dep_file(config,config_deployment_bkup):
     '''
     Checks the presence of master fag must be true for only once
     '''

     logger.info("checking Master Flag params for dynamic deployment")
     all_data_dictforKubernetesParams=config_deployment_bkup.get("kubernetes")
     all_data_dictForNetworkParams=config_deployment_bkup.get("kubernetes").get("Networks")
     all_data_dictforKubernetesParams_dynamic_dep=config.get("kubernetes")
     all_data_dictForNetworkParams_dynamic_dep=config.get("kubernetes").get("Networks")
     listForCNI_Confparams =[]
     listForCNI_ConfparamsDynamicDep =[]
     count=0
     isMasterval=all_data_dictForNetworkParams[0].values()[0]["isMaster"]
     
     if isMasterval=="true":
          count=count+1
          
     if True:
          for Allkeys in all_data_dictForNetworkParams[1]:
               for KeysInAllKeys in all_data_dictForNetworkParams[1][Allkeys]:
                    datainCNI_Conf=KeysInAllKeys.get("CNI_Configuration")


               for element in datainCNI_Conf:
                   listForCNI_Confparams.extend(element.values()[0])


          for element in listForCNI_Confparams:
               
               if 'macvlan_networks' in element:
                    isMastervalforMacvlan=element['macvlan_networks']['isMaster']
                    if isMastervalforMacvlan=="True":
                         count=count+1
               if 'weave_network' in element:
                    isMastervalforweave=element['weave_network']['isMaster']
                    if isMastervalforweave=="True":
                         count=count+1
               if 'flannel_network' in element:
                    isMastervalforflannel=element['flannel_network']['isMaster']
                    if isMastervalforflannel=="True":
                         count=count+1
               
               if 'host' in element:
                    isMasterforSriov=element['host']['networks'][0]['isMaster'] 
                    if isMasterforSriov=="True":
                         count=count+1

          for Allkeys in all_data_dictForNetworkParams_dynamic_dep[0]:
               for KeysInAllKeys in all_data_dictForNetworkParams_dynamic_dep[0][Allkeys]:
                    datainCNI_ConfDynamicDep=KeysInAllKeys.get("CNI_Configuration")


               for element in datainCNI_ConfDynamicDep:
                   listForCNI_ConfparamsDynamicDep.extend(element.values()[0])


          for element in listForCNI_ConfparamsDynamicDep:
               
               if 'macvlan_networks' in element:
                    
                    #isMastervalforMacvlan1=element['macvlan_networks']['isMaster']
                    if element['macvlan_networks']['isMaster']=="true":
                         count=count+1
               
               if 'host' in element:
                    isMasterforSriov1=element['host']['networks'][0]['isMaster'] 
                    if isMasterforSriov1=="true":
                         count=count+1

     if count!=1:
          logger.info("isMaster is true more than 1 time")
          return False
     else:
          pass

################Function validate isMaster for dynamic dep and dep file End##########################

################Function validate masterflag dynamic dep Start##########################
def validate_masterflag_dynamic_dep(config):
     '''
     Checks the presence of master fag must be true for only once
     '''

     logger.info("checking Master Flag  params for dynamic deployment")
     all_data_dictforKubernetesParams=config.get("kubernetes")
     all_data_dictForNetworkParams=config.get("kubernetes").get("Networks")
     listForCNI_Confparams =[]
     count=0
    
     if True:
          for Allkeys in all_data_dictForNetworkParams[0]:
               for KeysInAllKeys in all_data_dictForNetworkParams[0][Allkeys]:
                    datainCNI_Conf=KeysInAllKeys.get("CNI_Configuration")


               for element in datainCNI_Conf:
                   listForCNI_Confparams.extend(element.values()[0])


          for element in listForCNI_Confparams:
               
               if 'macvlan_networks' in element:
                    isMastervalforMacvlan=element['macvlan_networks']['isMaster']
                    if isMastervalforMacvlan=="True":
                         count=count+1
               
               if 'host' in element:
                    isMasterforSriov=element['host']['networks'][0]['isMaster'] 
                    if isMasterforSriov=="True":
                         count=count+1
     if count!=0:
          logger.info("isMaster is true more than 1 time")
          return False
     else:
          pass
################Function validate masterflag dynamic dep End##########################

################Function validate dynamic deployment file Start##########################
def validate_dynamic_deployment_file(config,config_deployment_bkup):
  '''
  Calls all the validations
  '''
  logger.info("validate_dynamic_deployment_file function for dynamic deployment")
  index = 0

  if validate_isMaster_for_dynamic_dep_and_dep_file(config,config_deployment_bkup)==False:
       exit(1)
  
  if validate_Kubernetes_tag(config)==False:
       exit(1)
   
  if validate_node_config_tag(config)==False:
       exit(1)
  
  if validate_node_config_params(config)==False:
       exit(1)
  
  if validate_network__tag(config)==False:
       exit(1)

  if validate_multus_network_CNI(config,index)==False:
       exit(1)
  
  if validate_multus_network_cniConf(config,index)==False:
       exit(1)
  
  if validate_cni_params_for_dynamic_deployment(config)==False:
       exit(1)
  
  if validate_multus_network_CNIdhcp(config,index)==False:
       exit(1)
  
  if validate_multus_network_CNIconf__params_for_dynamic_deployment(config)==False:
       exit(1)

  if validate_dhcpmandatory(config,index)==False:
      exit(1)
  
  else:
       pass

################Function validate dynamic deployment file End##########################
#################################Dynamic Deployment Validation End############################################


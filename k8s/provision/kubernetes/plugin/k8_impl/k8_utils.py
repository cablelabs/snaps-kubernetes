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

"""
Purpose : kubernetes Provisioning
Date :27/12/2017
Created By :Aricent
"""
import subprocess
import os
import sys
from common.utils import file_utils
from ansible_p.ansible_utils import ansible_configuration
from ansible_p.ansible_utils import ansible_playbook_launcher
import logging
import random
import shutil
import time,sys
import re
import netaddr
from common.consts import consts
from collections import OrderedDict
logger = logging.getLogger('deploy_venv')
def main(config, operation):
 ret = False
 if config:
  logger.info("********host entries ****************")
  hosts=config.get(consts.KUBERNETES).get(consts.HOSTS)
  __addansiblehosts(hosts);
  proxy_dic=__create_proxy_dic(config)
  logger.info("***********************PROXY****************************")
  logger.info(proxy_dic)
  #deployment_type=config.get(consts.KUBERNETES ).get(consts.DEPLOYMENT_TYPE)
  #ret = ansible_configuration.provision_preparation(proxy_dic,deployment_type,"False")
  ret = ansible_configuration.provision_preparation(proxy_dic,"False")
  if(ret!=True):
    logger.info('FAILED IN SET PROXY')
    exit(1)
  
  logger.info("***********************enable ssh key**************************")
  hosts=config.get(consts.KUBERNETES).get(consts.HOSTS)
  __enable_key_ssh(hosts);
  hostname_map=__get_hostname_map(hosts)
  print hostname_map 
  host_node_type_map= __create_host_nodetype_map(hosts)
  print host_node_type_map 
  hosts_data_dict=get_sriov_nw_data(config)
  host_port_map= __create_host_port_map(hosts)
  #yashwant chnages for duplicate ip check start
  networks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
  default_network_items=get_network_item(networks,"Default_Network").get("Default_Network")
  multus_network = get_multus_network(networks).get("Multus_network")
  #print multus_network
  multus_cni=get_multus_network_elements(multus_network, "CNI")
  multus_cni_configuration=get_multus_network_elements(multus_network, "CNI_Configuration")
  if(None != multus_cni):
    range_network_list=getNetworkIpRange(hostname_map=hostname_map, multus_cni=multus_cni, networks=multus_cni_configuration,default_network_items=default_network_items)
    ret=validateNetworkIpRange(range_network_list[0], range_network_list[1], range_network_list[2])
    if (ret != True):
      logger.info('VALIDATION FAILED IN NETWORK CONFIGURATION: OVERLAPPING IPS ARE FOUND')
      exit(0)
  #yashwant chnages for duplicate ip check end

  logger.info("PROVISION_PREPARATION AND DEPLOY METHOD CALLED")
  Networks=config.get(consts.KUBERNETES).get(consts.NETWORKS)
  logger.info(Networks)
  for item1 in Networks:
     for key in item1:
         if key == "Default_Network":
           default_network=item1.get(consts.DEFAULT_NETWORK)
           if(None != default_network):
              service_subnet =default_network.get(consts.SERVICE_SUBNET)
              logger.info("Service subnet = "+service_subnet )
              pod_subnet = default_network.get(consts.POD_SUBNET)
              logger.info("pod_subnet = "+pod_subnet)
              networking_plugin= default_network.get(consts.NETWORKING_PLUGIN)
              logger.info("networking_plugin= "+networking_plugin)
               
  enable_istio= config.get(consts.KUBERNETES).get(consts.ENABLE_ISTIO)
  enable_ambassador= config.get(consts.KUBERNETES).get(consts.ENABLE_AMBASSADOR)
  ambassador_rbac= config.get(consts.KUBERNETES).get(consts.AMBASSADOR_RBAC)
  logger.info(enable_istio)
  docker_repo= config.get(consts.KUBERNETES).get(consts.DOCKER_REPO)
  if (None != docker_repo):
     docker_ip= config.get(consts.KUBERNETES).get(consts.DOCKER_REPO).get(consts.IP)
     docker_port= config.get(consts.KUBERNETES).get(consts.DOCKER_REPO).get(consts.PORT)
     docker_user= config.get(consts.KUBERNETES).get(consts.DOCKER_REPO).get(consts.USER)
     docker_pass= config.get(consts.KUBERNETES).get(consts.DOCKER_REPO).get(consts.PASSWORD)
     logger.info("***********************enable ssh key**************************")
     __pushing_key(docker_ip,docker_user,docker_pass);

#################################################################################################
  hosts=config.get(consts.KUBERNETES).get(consts.HOSTS)
  Project_name=config.get(consts.KUBERNETES).get(consts.PROJECT_NAME)
  logger.info('********Project Name********')
  logger.info(Project_name)
  Git_branch=config.get(consts.KUBERNETES).get(consts.GIT_BRANCH)
  logger.info('Git Branch Name')
  logger.info(Git_branch)
  ret = ansible_configuration.launch_provisioning_kubernetes(hostname_map,host_node_type_map,host_port_map,service_subnet,pod_subnet,networking_plugin,enable_istio,docker_repo,hosts,Git_branch,enable_ambassador,ambassador_rbac,Project_name)
  if(ret!=True):
    logger.info('FAILED IN DEPLOY')
    exit(1)
#  logger.info("********Enabling Authentication ****************")
#  basic_authentication=config.get(consts.KUBERNETES).get(consts.BASIC_AUTHENTICATION)
#  print basic_authentication
#  ret = __enabling_basic_authentication(basic_authentication,Project_name);
#  if(ret!=True):
#    logger.info('FAILED IN DEPLOY')
#    exit(1)

#  logger.info("********etcd changes ****************")
#  ret = _modifying_etcd_node(Project_name);
#  if(ret!=True):
#    logger.info('FAILED IN DEPLOY')
#    exit(1)
  '''
  # changes by yashwant for metrics server  --->start
  metrics_server = False
  # function to get metrics server tag from deployment.yaml file

  metrics_server = config.get(consts.KUBERNETES).get(consts.METRICS_SERVER)
  if (metrics_server == True):
  	logger.info("********Metrics server configuration********")
	ret = ansible_configuration.launch_metrics_server(hostname_map, host_node_type_map)
	if (ret != True):
		logger.info('FAILED IN METRICS SERVER CONFIGURATION')
	else:
		logger.info('METRICS SERVER CONFIGURED SUCCESSFULLY')
		# changes by yashwant for metrics server  --->end
  '''
	
  
  logger.info("***********************cephhost creation*****************")
  logger.info("********ceph host entries ****************")
  ceph_hosts=config.get(consts.KUBERNETES).get(consts.PERSISTENT_VOLUME).get(consts.CEPH_VOLUME)
  ceph_installed = False
  print ceph_hosts
  if(None != ceph_hosts):
    ceph_installed = True
  if(True == ceph_installed):
    __addansiblehosts(ceph_hosts);
    logger.info("***********************enable ssh key for ceph ip's**************************")
    __enable_key_ssh(ceph_hosts);
    ret = ansible_configuration.launch_ceph_kubernetes(hostname_map,host_node_type_map,hosts,ceph_hosts)
    if(ret!=True):
      logger.info('FAILED IN CEPH DEPLOY')
      exit(1)
  logger.info("***********************Persistent host volume Start*****************")
  persistent_vol= config.get(consts.KUBERNETES).get(consts.PERSISTENT_VOLUME).get(consts.HOST_VOL)
  persistent_installed = False
  print persistent_vol
  if(None != persistent_vol):
    persistent_installed = True
  if(True == persistent_installed):
    ret = ansible_configuration.launch_persitent_volume_kubernetes(hostname_map,host_node_type_map,hosts,persistent_vol)
    if(ret!=True):
      logger.info('FAILED IN DEPLOY')
      exit(1)
  logger.info("***********************Additioanl N/W plugins**************")
  logger.info("***********************multus_cni**************************")
  multus_cni_installed = False
  multus_enabled = get_multus_cni_value(config)
  print 'multus_enabled :',multus_enabled
  macvlan_cni = False
  macvlan_cni = get_macvlan_value(config)
  print 'macvlan value :',macvlan_cni
  dhcp_cni=get_dhcp_value(config)
  print 'dhcp value :',dhcp_cni

  if(True == multus_enabled):
      logger.info("***********************crdNetwork creation*****************")
      time.sleep(10)
      ret = ansible_configuration.launch_crd_network(hostname_map,host_node_type_map)
      if(ret!=True):
        logger.info('FAILED IN CRD CREATION')
        exit(1)

      ret = ansible_configuration.launch_multus_cni(hostname_map,host_node_type_map,service_subnet,pod_subnet,networking_plugin,enable_istio)
      print ret  
      if(ret!=True):
        logger.info('FAILED IN MULTUS CONFIGURATION')
        exit(1)
      else:
        logger.info('MULTUS CONFIGURED SUCCESSFULLY.. NOW CREATING DEFAULT PLUGIN NETWORK')
        multus_cni_installed = True
        if("none" != networking_plugin):
          ret = create_default_network_multus(config,hostname_map,host_node_type_map,service_subnet,pod_subnet,networking_plugin)
          if(ret!=True):
           logger.info('FAILED IN CREATING DEFAULT NETWORK')
          else: 
           logger.info('SUCCESSFULLY CREATED DEFAULT NETWORK')

      networks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
      multus_network = get_multus_network(networks).get("Multus_network")
      multus_cni=get_multus_network_elements(multus_network, "CNI")
      print 'multus_cni:',multus_cni
      for cni in multus_cni:
          print multus_cni_installed
          print 'cni:',cni
          if(True == multus_cni_installed):
              if("sriov" == cni):
                 logger.info("***********************Sriov Network Plugin*******************")
                 print "SRIOV CONFIGURATION STARTS"
                 Project_name=config.get(consts.KUBERNETES).get(consts.PROJECT_NAME)
                 ret = ansible_configuration.launch_sriov_cni_configuration(hostname_map,host_node_type_map,hosts_data_dict,Project_name)
                 ret = ansible_configuration.launch_sriov_network_creation(hostname_map,host_node_type_map,hosts_data_dict,Project_name)
                 if(ret!=True):
                   logger.info('FAILED IN SRIOV NW Creation ')
          
              elif(consts.FLANNEL == cni):
                 logger.info("***********************Flannel Network Plugin*******************")
                 ret = launch_flannel_interface(config,hostname_map,host_node_type_map,networking_plugin,Project_name)
                 ret = True
                 if(ret!=True):
                    logger.info('FAILED IN FLANNEL INTERFACE CREATION')
              elif(consts.WEAVE == cni):
                 logger.info("***********************Weave Network Plugin*******************")
                 ret = launch_weave_interface(config,hostname_map,host_node_type_map,service_subnet,pod_subnet,networking_plugin)
                 if(ret!=True):
                    logger.info('FAILED IN WEAVE INTERFACFE CREATION')
              elif("macvlan" == cni):
                 logger.info("***********************Macvlan Network Plugin*******************")
                 print "in macvlan"
 		 if(multus_cni_installed == True):
		   if(macvlan_cni== True):
		        logger.info('CONFIGURING MAC-VLAN')
			ret = macvlan_installtion(config)
		   else:
		     logger.info('MAC-VLAN CONFIGURATION  EXIT , REASON--> MACVLAN  IS DISABLED ')
		     ret=False
              elif("dhcp" == cni):
                 logger.info("***********************DHCP Network Plugin*******************")
                 print "in dhcp"
 		 if(multus_cni_installed == True):
		   if(dhcp_cni== True):
		        logger.info('CONFIGURING DHCP')
			ret = dhcp_installtion(config)
		   else:
		     logger.info('DHCP CONFIGURATION  EXIT , REASON--> DHCP  IS DISABLED ')
		     ret=False
	
          else:
            logger.info('MULTUS CNI INSTALLTION FAILED')
  else:
    logger.info('MULTUS CNI IS DISABLED')
 
  if(True == multus_cni_installed):
    time.sleep(100)
    ret = ansible_configuration.delete_existing_conf_files_after_additional_plugins(hostname_map,host_node_type_map,networking_plugin)
    print ret  
    if(ret!=True):
      logger.info('FAILED IN DELETING EXISTING CONF FILE')
      exit(1)
  
#  logger.info("***********************MACVLAN**************************")    
#  multus_cni= config.get(consts.KUBERNETES).get(consts.MULTUS_CNI)
  #multus_cni="enable"
  #additionalNetworkPlugins_map['macvlan'] ="enable"
  #macvlan="enable"
#  print "MACVLAN_CNI value-------------------------------------------------------------------"
#  print macvlan_cni
#
#  #additionalNetworkPlugins_map=__create_additionalNetworkPlugins_dic(config)
# 
##  if(multus_cni == "enable"):
##    #if(additionalNetworkPlugins_map['macvlan'] == "enable"):
#  if(multus_cni_installed == True):
#    if(macvlan_cni== True):
#             logger.info('CONFIGURING MAC-VLAN')
#             ret = configure_macvlan_interface(config)
#             #ret = configure_macvlan_networks(config)
#	     noOfhosts_fornetwork=config.get(consts.KUBERNETES).get(consts.HOSTS)
#             for macvlan_host_fornetwork in noOfhosts_fornetwork:
#				if macvlan_host_fornetwork != None:
#					 inetfaceDict_fornetwork=macvlan_host_fornetwork.get("host")
#					 print "--------------------------------------------------------------"
#					 hostname_fornetwork=inetfaceDict_fornetwork.get("hostname")
#					 node_type_fornetwork=inetfaceDict_fornetwork.get("node_type")
#					 #print hostname_fornetwork
#					 #print node_type_fornetwork
#					 if (node_type_fornetwork=="master"):
#					   #print "inside master\n"
#					   ret = configure_macvlan_networks(config,hostname_fornetwork)
#
#    else:
#          logger.info('MAC-VLAN CONFIGURATION  EXIT , REASON--> MACVLAN  IS DISABLED ')
#          ret=False
  logger.info("********Enabling Authentication ****************")
  basic_authentication=config.get(consts.KUBERNETES).get(consts.BASIC_AUTHENTICATION)
  print basic_authentication
  ret = __enabling_basic_authentication(basic_authentication,Project_name);
  if(ret!=True):
    logger.info('FAILED IN DEPLOY')
    exit(1)
 
  logger.info("********etcd changes ****************")
  ret = _modifying_etcd_node(Project_name,hostname_map, host_node_type_map);
  if(ret!=True):
    logger.info('FAILED IN DEPLOY')
    exit(1) 
  logger.info("********Metrics Server ****************")
  # changes by yashwant for metrics server  --->start
  metrics_server = False

  metrics_server = config.get(consts.KUBERNETES).get(consts.METRICS_SERVER)
  if (metrics_server == True):
      logger.info("********Metrics server configuration********")
      ret = ansible_configuration.launch_metrics_server(hostname_map, host_node_type_map)


  return ret



def ip_var_args(*argv):#added by yashwant
    if (len(argv) % 2 ):
        print "Invalid configuration"
        exit()

    for i in range(len(argv)):
        if (i%2):
            continue

        startIP=int(netaddr.IPAddress(argv[i]))
        endIP=int(netaddr.IPAddress(argv[i+1]))
        for j in range(len(argv)):
            if (j%2):
                continue
            if (i == j):
                continue
            if (int(netaddr.IPAddress(argv[j])) <= startIP <= int(netaddr.IPAddress(argv[j+1])) or  int(netaddr.IPAddress(argv[j])) <= endIP <= int(netaddr.IPAddress(argv[j+1]))):
                print "Alert ! IPs ranges are intermingled"
                return False
	return True 

def validateNetworkIpRange(networkNameList,rangeStartDict,rangeEndDict):# added  by yashwant
 #print networkNameList
 #print rangeStartDict
 #print rangeEndDict
 final_list = []
 ret = True
 print "*********check duplicate in start range *********"
 checkDuplicateInStartEndIp(networkNameList,rangeStartDict)
 print "*********check duplicate in end range *********"
 checkDuplicateInStartEndIp(networkNameList,rangeEndDict)
 print "*********check duplicate start range with end range *********"
 #checkDuplicateStartIpWithEndIp(networkNameList,rangeStartDict,rangeEndDict)
 count=0
 lengthOfElements=len(networkNameList)
 #print lengthOfElements
 while (count < int(lengthOfElements)):
     count1=count+1
     while(count1 < int(lengthOfElements)):
         #print "--START--"+str(rangeStartDict.get(networkNameList[count]))+"--END--"+str(rangeEndDict.get(networkNameList[count]))
         #print "--COMARE WITH--"
         #print "--START--"+str(rangeStartDict.get(networkNameList[count1]))+"--END--"+str(rangeEndDict.get(networkNameList[count1]))
         if ip_var_args(rangeStartDict.get(networkNameList[count]),rangeEndDict.get(networkNameList[count]),rangeStartDict.get(networkNameList[count1]),rangeEndDict.get(networkNameList[count1])) == False:
             return False
         count1=count1+1
     count=count+1
 return  ret



def checkDuplicateInStartEndIp(networkNameList,rangeDict):#added  by yashwant
 final_list = []
 for network in networkNameList:
	if rangeDict.get(network) not in final_list:
		final_list.append(rangeDict.get(network))
	else:
		print "duplicate found:: ---network name "+str(network)+ " ---ip "+str(rangeDict.get(network))
		print "check range of below networks****"
		for key in rangeDict:
			if rangeDict[key] == rangeDict.get(network):
				print key
			
		return False 
		
 return True

def get_multus_network(networks):
     for network_item in networks:
         for key in network_item:
             #print key
             if key == "Multus_network":
                 return network_item


def get_network_item(networks, network_list_item):
    for network_item in networks:
        for key in network_item:
            # print key
            if key == network_list_item: #"Default_Network":
                return network_item

def get_multus_network_elements(multus_network, element):
    for item in multus_network:
        for key in item:
            if key == element:
                return item[key]



def networkDict(networks,type):
 for network in networks:
	for key in network:
		if key ==type:
			return network.get(type)

def getNetworkIpRange(**kargs):
 hostname_map=kargs.get("hostname_map")
 multus_cni=kargs.get("multus_cni")
 networks=kargs.get("networks")
 default_network_items = kargs.get("default_network_items")#default_network_items
 start_range_dict={}
 end_range_dict={}
 network_name_list=[]
 #print networkDict(networks, "Flannel")
 print "##############!!!@@###YASHAT^^^#########"
 default_cni_plugin=default_network_items.get("networking_plugin")

 if default_cni_plugin is None :
     start_range_dict = {}
     end_range_dict = {}
     network_name_list = []
 '''
 elif default_cni_plugin=="weave":
     print default_cni_plugin
     network_name_list.append(default_network_items.get("network_name"))
     start_range_dict[default_network_items.get("network_name")] = default_network_items.get("rangeStart")
     end_range_dict[default_network_items.get("network_name")] = default_network_items.get("rangeEnd")
 elif default_cni_plugin=="flannel":
     print default_cni_plugin
     network_name_list.append(default_network_items.get("network_name"))
     start_range_dict[default_network_items.get("network_name")] = default_network_items.get("rangeStart")
     end_range_dict[default_network_items.get("network_name")] = default_network_items.get("rangeEnd")
 '''
 for cni in multus_cni:
        #print cni
        if cni=="flannel" and default_cni_plugin != "flannel":
                #print "Flannel"
                for flannel_network in networkDict(networks,"Flannel"):
                        pass
                        #print flannel_network.get("flannel_networks")
                        #print flannel_network.get("host").get("flannel_networks")

        elif cni=="sriov":
                #print "check Sriov range"
                #print networkDict(networks,"SRIOV")
                for host in networkDict(networks,"Sriov"):
                        #print host
                        for key in host :
                                for network_item in host.get(key).get('networks'):
                                    if network_item.get("type")=="host-local":
                                            start_range_dict[network_item.get("network_name")]=network_item.get("rangeStart")
                                            end_range_dict[network_item.get("network_name")]=network_item.get("rangeEnd")
                                            network_name_list.append(network_item.get("network_name"))
                                            #print network_item.get("rangeEnd")
                                            #print network_item.get("rangeStart")
        elif cni=="weave" and default_cni_plugin != "weave" :
                #print "check Weave range"
                for weave_network in networkDict(networks,"Weave"):
                        pass
                        #print weave_network.get("weave_network").get("network_name")
                        #print weave_network.get("weave_network").get("rangeStart")
                        #print weave_network.get("weave_network").get("rangeEnd")
                        #start_range_dict[weave_network.get("weave_network").get("network_name")]= weave_network.get("weave_network").get("rangeStart")
                        #end_range_dict[weave_network.get("weave_network").get("network_name")]= weave_network.get("weave_network").get("rangeEnd")
                        #network_name_list.append(weave_network.get("weave_network").get("network_name"))
        elif cni=="macvlan":
                #print "check Macvlan range"
                #print networkDict(networks,"MACVLAN")
                for macvlan_network in networkDict(networks,"Macvlan"):
                        if macvlan_network.get("macvlan_networks").get("type")=="host-local":
                                #print macvlan_network.get("macvlan_networks").get("network_name")
                                #print macvlan_network.get("macvlan_networks").get("rangeStart")
                                #print macvlan_network.get("macvlan_networks").get("rangeEnd")
                                start_range_dict[macvlan_network.get("macvlan_networks").get("network_name")]=macvlan_network.get("macvlan_networks").get("rangeStart")
                                end_range_dict[macvlan_network.get("macvlan_networks").get("network_name")]=macvlan_network.get("macvlan_networks").get("rangeEnd")
                                network_name_list.append(macvlan_network.get("macvlan_networks").get("network_name"))
 return network_name_list,start_range_dict,end_range_dict
def clean_k8(config, operation):
  """
  This method is used for cleanup of kubernetes cluster
  :param config :input configuration file
  :return ret :t/f
  """
  ret = False
  if config:
   logger.info("******** host entries in /etc/ansible/host file****************")
   hosts=config.get(consts.KUBERNETES).get(consts.HOSTS)
   __addansiblehosts(hosts);
   __enable_key_ssh(hosts);
   logger.info("********host name map****************")
   hostname_map=__get_hostname_map(hosts)
   host_node_type_map= __create_host_nodetype_map(hosts)
   print host_node_type_map
   enable_istio= config.get(consts.KUBERNETES).get(consts.ENABLE_ISTIO)
   enable_ambassador= config.get(consts.KUBERNETES).get(consts.ENABLE_AMBASSADOR)
   ambassador_rbac= config.get(consts.KUBERNETES).get(consts.AMBASSADOR_RBAC)
   Git_branch=config.get(consts.KUBERNETES).get(consts.GIT_BRANCH)
   logger.info('Git Branch Name')
   logger.info(Git_branch)
   Project_name=config.get(consts.KUBERNETES).get(consts.PROJECT_NAME)
   logger.info('********Project Name********')
   logger.info(Project_name)

   Networks=config.get(consts.KUBERNETES).get(consts.NETWORKS)
   logger.info(Networks)
   for item1 in Networks:
     for key in item1:
       if key == "Default_Network":
          default_network=item1.get(consts.DEFAULT_NETWORK)
          if(None != default_network):
             service_subnet =default_network.get(consts.SERVICE_SUBNET)
             logger.info("Service subnet = "+service_subnet )
             pod_subnet = default_network.get(consts.POD_SUBNET)
             logger.info("pod_subnet = "+pod_subnet)
             networking_plugin= default_network.get(consts.NETWORKING_PLUGIN)
             logger.info("networking_plugin= "+networking_plugin)
          else:
             logger.info("error: Default network configurations are not defined")


   ret = clean_up_flannel(hostname_map,host_node_type_map,networking_plugin,config,Project_name)
   if(ret!=True):
     logger.info('FAILED IN FLANNEL CLEANUP')

   ret = clean_up_weave(hostname_map,host_node_type_map,networking_plugin,config,Project_name)
   if(ret!=True):
     logger.info('FAILED IN WEAVE CLEANUP')

   print "MACVLAN REMOVAL FOR CLUSTER-------------------------"
   ret = macvlan_cleanup(config)
   if ret == True:
		print "##################MACVLAN REMOVED SUCCESSFULLY################"
   elif ret == False :
		print "################MACVLAN NOT REMOVED######################"
   metrics_server = config.get(consts.KUBERNETES).get(consts.METRICS_SERVER)
   logger.info("metrics_server flag in kube8 deployment file is " + str(metrics_server))
   ansible_configuration.clean_up_k8_addons(hostname_map=hostname_map, host_node_type_map=host_node_type_map,
                                            metrics_server=metrics_server)
   ret = ansible_configuration.clean_up_k8(enable_istio,Git_branch,enable_ambassador,ambassador_rbac,Project_name)
   if(ret!=True):
    logger.info('FAILED IN CLEANUP')
    exit(1)

   return ret

#def dynamic_clean_nodes(config, operation):
#  """
#  This method is used for clean nodes of kubernetes cluster
#  :param config :input configuration file
#  :return ret :t/f
#  """
#  ret = False
#  if config:
#   logger.info("********host name map****************")
#   hosts=config.get(consts.KUBERNETES).get(consts.DYNAMIC_HOSTS)
#   hostname_map=__get_hostname_map(hosts)
#   print hostname_map
#   ret = ansible_configuration.clean_up_k8_nodes(hostname_map)
#   if(ret!=True):
#    logger.info('FAILED IN CLEANUP nodes')
#    exit(1)
#   return ret

#def dynamic_deploy_nodes(config, operation):
def dynamic_node_add_and_del(config, operation):
  """
  This method is used for deploy nodes of kubernetes cluster
  :param config :input configuration file
  :return ret :t/f
  """
  ret = False
  if config:

   logger.info("********dynamic host entries in /etc/ansible/host file****************")
   hosts=config.get(consts.KUBERNETES).get(consts.HOSTS)
   __addansiblehosts(hosts);
   logger.info("********enable ssh on dynamic host****************")
   __enable_key_ssh(hosts);
   logger.info("********dynamic host name map list****************")
   dynamic_hostname_map=__get_hostname_map(hosts)
   logger.info("Dynamic hostname and IP map")
   logger.info(dynamic_hostname_map)
   logger.info("********dynamic host name and node type map list****************")
   dynamic_host_node_type_map= __create_host_nodetype_map(hosts)
   logger.info("Dynamic hostname and node type map")
   logger.info(dynamic_host_node_type_map)
   logger.info("***********************HOST NAME LIST**************************")
   hostnamelist =__hostname_list(hosts)
   logger.info("Dynamic hostname list")
   logger.info(hostnamelist)
   Project_name=config.get(consts.KUBERNETES).get(consts.PROJECT_NAME)
   hostname_map=__get_hostname_map(hosts)
   host_node_type_map= __create_host_nodetype_map(hosts)
   print hostname_map
   host_port_map= __create_host_port_map(hosts)
   print "cluster port map"
   print host_port_map
   print host_node_type_map
   master_ip = get_master_ip(Project_name)
   print master_ip
   
   if (operation is "dynamic_deploy_k8"):
 
    logger.info("*********Deploy dynamic node *******")
    ret = ansible_configuration.deploy_k8_nodes(hostnamelist,dynamic_hostname_map,dynamic_host_node_type_map,host_port_map,hosts,Project_name,master_ip)
    if(ret!=True):
      logger.info('FAILED IN DEPLOY NODES')
      exit(1)

    logger.info("***********************multus_cni dynamic node**************************")
    multus_cni_installed = False
    multus_enabled = get_multus_cni_value(config)
    print 'multus_enabled :',multus_enabled
    macvlan_cni = False
    macvlan_cni = get_macvlan_value(config)
    print 'macvlan value :',macvlan_cni
    dhcp_cni=get_dhcp_value(config)
    print 'dhcp value for dynamic added node: ',dhcp_cni

    networks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
    multus_network = get_multus_network(networks).get("Multus_network")
    multus_cni=get_multus_network_elements(multus_network, "CNI")
    if(True == multus_enabled):
      ret = ansible_configuration.launch_multus_cni_dynamic_node(hostname_map,host_node_type_map,dynamic_hostname_map,dynamic_host_node_type_map,master_ip,Project_name)
      print ret  
      if(ret!=True):
        logger.info('FAILED IN MULTUS CONFIGURATION')
        exit(1)
      else:
        logger.info('MULTUS CONFIGURED SUCCESSFULLY')
        multus_cni_installed = True 
  
      if(True == multus_cni_installed):
        for cni in multus_cni:
          print multus_cni_installed
          print cni
          if(consts.FLANNEL == cni):
            logger.info('FLANNEL PLUGIN IS ONLY SUPPORTED AT INIT TIME')
          elif(consts.WEAVE == cni):
            logger.info('WEAVE PLUGIN IS ONLY SUPPORTED AT INIT TIME')
          elif("sriov" == cni):
            logger.info("***********************SRIOV CONFIGURATION ON DYNAMIC NODES *******************")
            host_node_type_map= __create_host_nodetype_map(hosts)
            hosts_data_dict=get_sriov_nw_data(config)
            Project_name=config.get(consts.KUBERNETES).get(consts.PROJECT_NAME)
            ansible_configuration.launch_sriov_cni_configuration(dynamic_hostname_map,dynamic_host_node_type_map,hosts_data_dict,Project_name)
            ret = ansible_configuration.launch_sriov_network_creation(dynamic_hostname_map,dynamic_host_node_type_map,hosts_data_dict,Project_name)
            if(ret!=True):
                logger.info('SRIOV CONFIGURATION FAILED IN DYNAMIC NODES')
               
          elif ("macvlan" == cni):
		print "MACVLAN INSTALLATION ON DYNAMICALLY ADDED NODES---------------------"
		ret = macvlan_creation_node(config,multus_cni_installed)
		if ret == True:
			print "Macvlan installed for node"
		elif ret == False:
			print "Macvlan not installed on nodes"
		
      time.sleep(100)
      ret = ansible_configuration.delete_existing_conf_files(dynamic_hostname_map,dynamic_host_node_type_map,Project_name)
      print ret  
      if(ret!=True):
         logger.info('FAILED IN DELETING EXISTING CONF FILE')
         exit(1)

      elif("dhcp" == cni):
                 logger.info("***********************DHCP Network Plugin dynamic added node*******************")
                 print "in dhcp"
                 if(multus_cni_installed == True):
                   if(dhcp_cni== True):
                        logger.info('CONFIGURING DHCP')
                        ret = dhcp_installtion(config)
                   else:
                     logger.info('DHCP CONFIGURATION  EXIT , REASON--> DHCP  IS DISABLED ')
                     ret=False


		
   elif (operation is "dynamic_clean_k8"):
    print "MACVLAN CLEANUP FOR DYNAMICALLY ADDED NODES"
    macvlan_cni = False
    macvlan_cni = get_macvlan_value(config)
    print 'macvlan value :',macvlan_cni
    if (macvlan_cni==True):
	    ret = macvlan_removal_node(config)
	    if ret == True:
			print "MACVLAN REMOVED FOR DYNAMICALLY ADDED NODES---------------------"
	    else :
			print "MACVLAN NOT REMOVED FOR DYNAMICALLY ADDED NODES---------------------"	
    else:
             logger.info('MAC-VLAN CONFIGURATION  EXIT , REASON--> MACVLAN  IS DISABLED ')
             ret=False

    logger.info("FLANNEL CLEANUP FOR DYNAMICALLY ADDED NODES")
    ret = ansible_configuration.clean_up_flannel_dynamic_node(dynamic_hostname_map,dynamic_host_node_type_map)
    if(ret!=True):
      logger.info("FLANNEL NOT REMOVED FOR DYNAMICALLY ADDED NODES")	

    ret = ansible_configuration.clean_up_weave_dynamic_node(dynamic_hostname_map,dynamic_host_node_type_map)
    if(ret!=True):
      logger.info("WEAVE NOT REMOVED FOR DYNAMICALLY ADDED NODES")	

    logger.info("*********Clean dynamic node *******")
    ret = ansible_configuration.clean_up_k8_nodes(hostnamelist,dynamic_hostname_map,dynamic_host_node_type_map,Project_name)
    if(ret!=True):
      logger.info('FAILED IN CLEAN NODES')
      exit(1)

   return ret

"""******** Pushing key to  host ***************"""
def __pushing_key(host_ip,user_name,password):
  logger.info('PUSHING KEY TO HOSTS')
  command= "sshpass -p %s ssh-copy-id -o StrictHostKeyChecking=no %s@%s" %(password,user_name,host_ip)
  res=subprocess.call(command,shell=True)
  if(res!=True):
    logger.info('ERROR IN PUSHING KEY:Probaly the key is already present in remote host')
  logger.info('SSH KEY BASED AUTH ENABLED')

"""******** Enable SSH key function ***************"""
def __enable_key_ssh(hosts):
 from pathlib import Path

 command="sed -i '/#host_key_checking/c\host_key_checking = False' " + consts.ANSIBLE_CONF
 subprocess.call(command ,shell=True)
 command_time="sed -i '/#timeout = 10/c\\timeout = 50' " + consts.ANSIBLE_CONF
 subprocess.call(command_time ,shell=True)
 for i in range(len(hosts)):
    user_name=hosts[i].get(consts.HOST).get(consts.USER)
    if user_name!='root':
       logger.info('USER MUST BE ROOT')
       exit(0)
    password=hosts[i].get(consts.HOST).get(consts.PASSWORD)
    host_ip=""
    ip=hosts[i].get(consts.HOST).get(consts.IP)
    host_ip=ip
    check_dir=os.path.isdir(consts.SSH_PATH)
    if not check_dir:
      os.makedirs(consts.SSH_PATH)
      print host_ip
      logger.info('GENERATING SSH KEY')
      subprocess.call('echo -e y|ssh-keygen -b 2048 -t rsa -f /root/.ssh/id_rsa -q -N ""', shell=True)
    check_dir=os.path.isdir(consts.SSH_PATH)
    if check_dir:
      id_rsa_pub = Path("/root/.ssh/id_rsa.pub")
      id_rsa = Path("/root/.ssh/id_rsa")
      if not id_rsa.is_file():
       if id_rsa_pub.is_file():
         os.remove("/root/.ssh/id_rsa.pub")
       logger.info('GENERATING SSH KEY')
       subprocess.call('echo -e y|ssh-keygen -b 2048 -t rsa -f /root/.ssh/id_rsa -q -N ""', shell=True)
      if not id_rsa_pub.is_file():
       if id_rsa.is_file():
         os.remove("/root/.ssh/id_rsa")
       logger.info('GENERATING SSH KEY')
       subprocess.call('echo -e y|ssh-keygen -b 2048 -t rsa -f /root/.ssh/id_rsa -q -N ""', shell=True)
      ip=hosts[i].get(consts.HOST).get(consts.IP)
      host_ip=ip
      logger.info('PUSHING KEY TO HOSTS')
      command= "sshpass -p '%s' ssh-copy-id -o StrictHostKeyChecking=no %s@%s" %(password,user_name,host_ip)
      logger.info(command)
      res=subprocess.call(command,shell=True)
      if(res!=True):
        logger.info('ERROR IN PUSHING KEY:Probaly the key is already present in remote host')
      logger.info('SSH KEY BASED AUTH ENABLED')
 return True

"""******** Creating Host name list function ***************"""
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

"""********  Creating proxy dictionary function ***************"""
def __create_proxy_dic(config):
 logger.info("Creating Proxy dictionary")
 proxy_dic={}
 http_proxy=config.get(consts.KUBERNETES ).get(consts.PROXIES).get(consts.HTTP_PROXY)
 https_proxy=config.get(consts.KUBERNETES ).get(consts.PROXIES).get(consts.HTTPS_PROXY)
 ftp_proxy=config.get(consts.KUBERNETES ).get(consts.PROXIES).get(consts.FTP_PROXY)
 no_proxy=config.get(consts.KUBERNETES ).get(consts.PROXIES).get(consts.NO_PROXY)
 proxy_dic['http_proxy']="\""+http_proxy+"\""
 proxy_dic['https_proxy']="\""+https_proxy+"\""
 proxy_dic['ftp_proxy']="\""+ftp_proxy+"\""
 proxy_dic['no_proxy']="\""+no_proxy+"\""
 logger.info("Done with proxies")
 return proxy_dic





def get_sriov_nw_data(config):
    noOfNetwroks=config.get(consts.KUBERNETES).get(consts.NETWORKS)
    for item1 in noOfNetwroks:
     for key in item1:
            print key
            if key == "Multus_network":
                multus_network=item1.get("Multus_network")
                for item2 in multus_network:
                   print item2
                   for key in item2:
                        print key
                        if key == "CNI_Configuration":
                                cni_configuration=item2.get("CNI_Configuration")
                                
    return cni_configuration
"""********  get credentials function ***************"""
def __get_credentials(config):
 credential_dic={}
 hosts=config.get(consts.KUBERNETES).get(consts.HOSTS)
 for i in range(len(hosts)):
  user=hosts[i].get(consts.HOST).get(consts.USER)
  password =hosts[i].get(consts.HOST).get(consts.PASSWORD)
  node_type=hosts[i].get(consts.HOST).get(consts.NODE_TYPE)
  credential_dic['user']=user
  credential_dic['password']=password
 return credential_dic

"""********  Get hostname map  function ***************"""
def __get_hostname_map(hosts):
 if hosts:
  hostname_map={}
  for i in range(len(hosts)):
    hostname=hosts[i].get(consts.HOST).get('hostname')
    host_ip=""
    ip=hosts[i].get(consts.HOST).get(consts.IP)
    if ip:
       host_ip=ip
    hostname_map[hostname]=host_ip
 return hostname_map


"""********  Basic Authentication function ***************"""

def __enabling_basic_authentication(basic_authentication,Project_name):
 for i in range(len(basic_authentication)):
  user_name=basic_authentication[i].get(consts.USER).get(consts.USER_NAME)
  user_password=basic_authentication[i].get(consts.USER).get(consts.USER_PASSWORD)
  user_id=basic_authentication[i].get(consts.USER).get(consts.USER_ID)
  ret = ansible_configuration.modify_user_list(user_name,user_password,user_id)
  if(ret!=True):
    logger.info('FAILED IN DEPLOY')
    exit(1)

 master_host_name = ansible_configuration.get_host_master_name(Project_name)
 #master_host_name = "kubemaster" 
 logger.info('UPDATE KUBE API MANIFEST FILE')
 ret = ansible_configuration.update_kube_api_manifest_file(master_host_name)
 if(ret!=True):
   logger.info('FAILED TO UPDATE KUBE API FILE')
   exit(1)
 time.sleep( 5 );
 
 return ret

"*********** etcd modification changes *************"

def _modifying_etcd_node(Project_name,hostname_map, host_node_type_map):
  #master_host_name = ansible_configuration.get_host_master_name(Project_name)
  #master_ip = get_master_ip(Project_name)
  for key, value in host_node_type_map.iteritems():
       node_type = value
       host_name = key
       if (node_type == "master" ):
           master_host_name= host_name
  for key, value in hostname_map.iteritems():
       ip=value
       host_name=key
       if (host_name == master_host_name ):
           master_ip= ip 
  logger.info('master ip --->'+master_ip+'  master host name --->'+ master_host_name)
  VARIABLE_FILE=consts.VARIABLE_FILE
  SRC_PACKAGE_PATH=consts.INVENTORY_SOURCE_FOLDER
  logger.info('EXECUTING ETCD Changes')
  playbook_path_etcd_changes=consts.ETCD_CHANGES
  logger.info(playbook_path_etcd_changes)
  ret_hosts=ansible_playbook_launcher.__launch_ansible_playbook_etcd_changes(playbook_path_etcd_changes,master_host_name,master_ip,SRC_PACKAGE_PATH,VARIABLE_FILE)
  if(ret_hosts!=True):
        logger.info('FAILED SET HOSTS PLAY')
        exit(1)
  return ret_hosts

"""********  Get Node types function ***************"""
def __create_host_nodetype_map(hosts):
 if hosts:
  hostnode_map={}
  host_ip=""
  for i in range(len(hosts)):
    node_type=hosts[i].get(consts.HOST).get(consts.NODE_TYPE)
    hostname=hosts[i].get(consts.HOST).get('hostname')
    hostnode_map[hostname]=node_type
 return hostnode_map

def __create_host_port_map(hosts):
 print hosts
 if hosts:
  hostport_map={}
  host_ip=""
  for i in range(len(hosts)):
    registry_port=hosts[i].get(consts.HOST).get('registry_port')
    hostname=hosts[i].get(consts.HOST).get('hostname')
    hostport_map[hostname]=registry_port
 return hostport_map
def __addansiblehosts(hosts):
   """
    This will add the ansible hosts into the ansible hosts file placed at /etc/ansible/hosts
   """
   if hosts:
      host_str=""
      ansible_host_str=""
      host_ip=""
      ansible_host_file=open(consts.ANSIBLE_HOSTS_FILE,"r+")
      host_file=open(consts.HOSTS_FILE,"r+")
      ansible_file_content=""
      file_content=""
      for line in ansible_host_file:
        ansible_file_content=ansible_file_content+line
      for line in host_file:
        file_content=file_content+line
      for i in range(len(hosts)):
        host_ip=hosts[i].get(consts.HOST).get(consts.IP)
	host_ip=host_ip+" "
        print host_ip
        host_name=hosts[i].get(consts.HOST).get(consts.HOSTNAME)
	host_name=host_name+" "
        print host_name
        if ((host_ip in ansible_file_content) and (host_name in ansible_file_content)):
            logger.info("")
        else:
            ansible_host_str=host_name+"\n"+host_ip+"\n"+ansible_host_str
        if ((host_ip in file_content) and (host_name in file_content)):
            logger.info("")
        else:
            host_str=host_ip+" "+host_name+"\n"+host_str
      logger.info(host_str)
      logger.info("****host entries in "+consts.HOSTS_FILE+"*******")
      host_file.write(host_str)
      logger.info("****host entries in "+consts.ANSIBLE_HOSTS_FILE+"*****")
      ansible_host_file.write(ansible_host_str)
      host_file.close()

"""******** Creating flannelNetwork list function ***************"""
def __noOfNetworkInFlannel_list(config):
 logger.info("Creating noOfNetworksInFlannel list")
 flannelNetworks=config.get(consts.KUBERNETES).get(consts.NETWORKS)
 print flannelNetworks 
 flannelNetworkList=[]
 for Network in flannelNetworks:
   if(Network != None):
     #print Network
     flannelNetworkList=Network.get(consts.FLANNEL_NETWORK)
     #print flannelNetworkList
 return flannelNetworks

"""******** Creating weaveNetwork list function ***************"""
def __noOfNetworkInWeave_list(config):
 logger.info("Creating noOfNetworksInWeave list")
 weaveNetworkList=[]
 hosts_data_dict=get_flannel_nw_data(config)
 for item1 in hosts_data_dict:
   for key in item1:
     if key == "Multus_network":
       multus_network=item1.get("Multus_network")
       for item2 in multus_network:
         for key in item2:
           if key == "CNI_Configuration":
             weaveNetworks=item2.get("CNI_Configuration")
             for item3 in weaveNetworks:
               for key in item3:
                 if(consts.WEAVE_NETWORK == key):
                   weaveNetworkList= item3.get(consts.WEAVE_NETWORK)
 
 #print weaveNetworks
 return weaveNetworks

"""******** Creating noOfNetworksInMacvlan list function ***************"""
def configure_macvlan_networks(config,macvlan_master_hostname):    #function for mac-vlan network creation
  """
  This method is used for create macvlan network after multus
  :param config :input configuration file
  :return ret :t/f
  """
  ret = False
  if config:
    macvlan_master_network_playbook=consts.K8_MACVLAN_MASTER_NETWORK_PATH
    macvlan_network_playbook=consts.K8_MACVLAN_NETWORK_PATH
    macvlan_master_network_dhcp_playbook=consts.K8_MACVLAN_MASTER_NETWORK_DHCP_PATH
    macvlan_network_dhcp_playbook=consts.K8_MACVLAN_NETWORK_DHCP_PATH
    macvlan_dhcp_daemon_playbook=consts.K8_DHCP_PATH	
    print "configure_mac_vlan networks"
    logger.info("********configure_mac_v_lan function****************")
    noOfNetwroksInMacvlan=config.get(consts.KUBERNETES).get(consts.NETWORK_CREATION_IN_MACVLAN)
    #print "NEW CODE-------------------------------------------"
    #print noOfNetwroksInMacvlan
    #print "\nEXIT FROM CODE $$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n"
    for item1 in noOfNetwroksInMacvlan:
     #print "CHIRAG IN ITEM1 @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
     #print item1
     for key in item1:
            #print "\nCHIRAG ITEM1 KEY IS ---------------------------@@@\n"
            #print key
            if key == "Multus_network":
                multus_network=item1.get("Multus_network")
                for item2 in multus_network:
                   #print "\n CHIRAG IN ITEM2%%%%%%%%%%%%%%%%%%%%%%\n"
                   #print item2
                   for key in item2:
                        #print "\n CHIRAG ITEM2 KEY in for loop"
                        #print key
                        if key == "CNI_Configuration":
                                cni_configuration=item2.get("CNI_Configuration")
                                for item3 in cni_configuration:
                                        #print "\n CHIRAG IN ITEM3"
                                        #print item3
                                        for key in item3:
                                                #print "\n CHIRAG IN ITEM3%%%%%%%%%%%%%%%%%%%"
                                                #print key
                                                if key == "Macvlan":
                                                       #print "\nHELLO IN MACVLAN\n"
                                                       macvlan_network1=item3.get("Macvlan")
                                                       for macvlan_networks in macvlan_network1:
 









#    noOfNetwroksInMacvlan=config.get(consts.KUBERNETES).get(consts.NETWORK_CREATION_IN_MACVLAN)
#    for item in noOfNetwroksInMacvlan:
#         #print"in ITEM %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%" 
#         #print item
#	 for key in item:
#		if key =="MACVLAN":
#         		macvlan_network1=item.get(consts.MACVLAN)
#			for macvlan_networks in macvlan_network1:
								  inetfaceDict=macvlan_networks.get("macvlan_networks")
				  	                          macvlan_gateway=inetfaceDict.get("gateway")              
							          macvlan_master=inetfaceDict.get("master")                
							          macvlan_masterplugin=inetfaceDict.get("masterplugin")    
							          macvlan_network_name=inetfaceDict.get("network_name")    
							          macvlan_rangeStart=inetfaceDict.get("rangeStart")        
							          macvlan_rangeEnd=inetfaceDict.get("rangeEnd")            
							          macvlan_routes_dst=inetfaceDict.get("routes_dst")        
							          macvlan_subnet=inetfaceDict.get("subnet")                
						#	          macvlan_subnetMin=inetfaceDict.get("subnetMin")          
							          macvlan_type=inetfaceDict.get("type")                    
				                                  macvlan_node_hostname=inetfaceDict.get("hostname")
							          print "-----------------------------------------------------------------------------------------------------------------------------------------------------------------------"
				                                  print "macvlan_node_hostname" ,macvlan_node_hostname
							          print "macvlan_gateway: ",macvlan_gateway                                    
							          print "macvlan_master_hostname: ",macvlan_master_hostname                                   
							          print "macvlan_master: ",macvlan_master                                     
							          print "macvlan_masterplugin: ",macvlan_masterplugin                               
							      	  print "macvlan_network_name: ",macvlan_network_name                               
							          print "macvlan_rangeStart: ",macvlan_rangeStart                                 
							          print "macvlan_rangeEnd: ",macvlan_rangeEnd                                   
							          print "macvlan_routes_dst: ",macvlan_routes_dst                                 
							          print "macvlan_subnet: ",macvlan_subnet                                     
						#	          print macvlan_subnetMin                                  
						                  print "macvlan_type: ",macvlan_type                                 
						       
						                  if macvlan_masterplugin == True:
										    if macvlan_type == "host-local":
											print "Master plugin is true && type is host-local"
						                                        ret=ansible_playbook_launcher.__launch_ansible_playbook_network_creation(macvlan_master_network_playbook,macvlan_master_hostname,macvlan_network_name,macvlan_master,macvlan_subnet,macvlan_rangeStart,macvlan_rangeEnd,macvlan_routes_dst,macvlan_gateway)
						                                    	if (ret==False):
												logger.info('FAILED IN MACVLAN network creation_master1')
						#						exit(1)
										    if macvlan_type == "dhcp":
											print "Master plugin is true && type is dhcp"
						                                        ret=ansible_playbook_launcher.__launch_ansible_playbook_network_dhcp_creation(macvlan_master_network_dhcp_playbook,macvlan_master_hostname,macvlan_network_name,macvlan_master)
						                        		#print "DHCP DAEMON RUNNING"
				                                                        #ansible_playbook_launcher.__launch_ansible_playbook__dhcp_daemon_creation(macvlan_dhcp_daemon_playbook,macvlan_node_hostname)
				                                                        if (ret==False):
												logger.info('FAILED IN MACVLAN network creation_master2')
						#						exit(1)
				
						                  if macvlan_masterplugin == False:
										    if macvlan_type == "host-local":
												print "Master plugin is false && type is host-local"
												ret=ansible_playbook_launcher.__launch_ansible_playbook_network_creation(macvlan_network_playbook,macvlan_master_hostname,macvlan_network_name,macvlan_master,macvlan_subnet,macvlan_rangeStart,macvlan_rangeEnd,macvlan_routes_dst,macvlan_gateway)
								                                if (ret==False):
													logger.info('FAILED IN MACVLAN network creation1')
						#							exit(1)
										    if macvlan_type == "dhcp":
											print "Master plugin is false && type is dhcp"
											ret=ansible_playbook_launcher.__launch_ansible_playbook_network_dhcp_creation(macvlan_network_dhcp_playbook,macvlan_master_hostname,macvlan_network_name,macvlan_master)
				                                                        #print "DHCP DAEMON RUNNING"
				                                                        #ansible_playbook_launcher.__launch_ansible_playbook__dhcp_daemon_creation(macvlan_dhcp_daemon_playbook,macvlan_node_hostname)
				 
									                if (ret==False):
												logger.info('FAILED IN MACVLAN network creation2')
						#						exit(1)
						       
						
  return ret







"""******** Removing NetworksInMacvlan list function ***************"""
def remove_macvlan_networks(config,macvlan_master_hostname):    #function for mac-vlan network removal
  """
  This method is used for create macvlan network after multus
  :param config :input configuration file
  :return ret :t/f
  """
  ret = False
  if config:
#    macvlan_master_network_playbook=consts.K8_MACVLAN_MASTER_NETWORK_PATH
#    macvlan_network_playbook=consts.K8_MACVLAN_NETWORK_PATH
#    macvlan_master_network_dhcp_playbook=consts.K8_MACVLAN_MASTER_NETWORK_DHCP_PATH
#    macvlan_network_dhcp_playbook=consts.K8_MACVLAN_NETWORK_DHCP_PATH
#    macvlan_dhcp_daemon_playbook=consts.K8_DHCP_PATH	
    macvlan_network_removal_playbook=consts.K8_MACVLAN_NETWORK_REMOVAL_PATH
    dhcp_daemon_removal_playbook=consts.K8_DHCP_REMOVAL_PATH
    print "Removal_mac_vlan networks"
    logger.info("********removal_mac_v_lan function****************")
    noOfNetwroksInMacvlan=config.get(consts.KUBERNETES).get(consts.NETWORK_CREATION_IN_MACVLAN)
    #print "NEW CODE-------------------------------------------"
    #print noOfNetwroksInMacvlan
    #print "\nEXIT FROM CODE $$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n"
    for item1 in noOfNetwroksInMacvlan:
     #print "CHIRAG IN ITEM1 @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
     #print item1
     for key in item1:
            #print "\nCHIRAG ITEM1 KEY IS ---------------------------@@@\n"
            #print key
            if key == "Multus_network":
                multus_network=item1.get("Multus_network")
                for item2 in multus_network:
                   #print "\n CHIRAG IN ITEM2%%%%%%%%%%%%%%%%%%%%%%\n"
                   #print item2
                   for key in item2:
                        #print "\n CHIRAG ITEM2 KEY in for loop"
                        #print key
                        if key == "CNI_Configuration":
                                cni_configuration=item2.get("CNI_Configuration")
                                for item3 in cni_configuration:
                                        #print "\n CHIRAG IN ITEM3"
                                        #print item3
                                        for key in item3:
                                                #print "\n CHIRAG IN ITEM3%%%%%%%%%%%%%%%%%%%"
                                                #print key
                                                if key == "Macvlan":
                                                       #print "\nHELLO IN MACVLAN\n"
                                                       macvlan_network1=item3.get("Macvlan")
                                                       for macvlan_networks in macvlan_network1:
								  inetfaceDict=macvlan_networks.get("macvlan_networks")
				  	                          macvlan_gateway=inetfaceDict.get("gateway")              
							          macvlan_master=inetfaceDict.get("master")                
							          macvlan_masterplugin=inetfaceDict.get("masterplugin")    
							          macvlan_network_name=inetfaceDict.get("network_name")    
							          macvlan_rangeStart=inetfaceDict.get("rangeStart")        
							          macvlan_rangeEnd=inetfaceDict.get("rangeEnd")            
							          macvlan_routes_dst=inetfaceDict.get("routes_dst")        
							          macvlan_subnet=inetfaceDict.get("subnet")                
						#	          macvlan_subnetMin=inetfaceDict.get("subnetMin")          
							          macvlan_type=inetfaceDict.get("type")                    
				                                  macvlan_node_hostname=inetfaceDict.get("hostname")
							          print "-----------------------------------------------------------------------------------------------------------------------------------------------------------------------"
				                                  print "macvlan_node_hostname" ,macvlan_node_hostname
							          print "macvlan_gateway: ",macvlan_gateway                                    
							          print "macvlan_master_hostname: ",macvlan_master_hostname                                   
							          print "macvlan_master: ",macvlan_master                                     
							          print "macvlan_masterplugin: ",macvlan_masterplugin                               
							      	  print "macvlan_network_name: ",macvlan_network_name                               
							          print "macvlan_rangeStart: ",macvlan_rangeStart                                 
							          print "macvlan_rangeEnd: ",macvlan_rangeEnd                                   
							          print "macvlan_routes_dst: ",macvlan_routes_dst                                 
							          print "macvlan_subnet: ",macvlan_subnet                                     
						#	          print macvlan_subnetMin                                  
						                  print "macvlan_type: ",macvlan_type                                 
						       
						                  ret=ansible_playbook_launcher.__launch_ansible_playbook_network_removal(macvlan_network_removal_playbook,macvlan_master_hostname,macvlan_network_name)
						                  if (ret==False):
										logger.info('FAILED IN MACVLAN network removal_master')

                                                                  if macvlan_type == "dhcp":
                                                                                        print "DHCP DAEMON REMOVING-------------"
                                                                                        ret=ansible_playbook_launcher.__launch_ansible_playbook__dhcp_daemon_removal(dhcp_daemon_removal_playbook,macvlan_node_hostname)
                                                                                        if (ret==False):
                                                                                                logger.info('FAILED IN DHCP REMOVAL---------------')


  return ret

###############interface creation#########################


"""******** Creating interaface list function ***************"""
def configure_macvlan_interface(config):    #function for mac-vlan network creation
  """
  This method is used for create macvlan network after multus
  :param config :input configuration file
  :return ret :t/f
  """
  ret = False
  if config:
    vlan_playbook=consts.K8_VLAN_INTERFACE_PATH
    print "configure_mac_vlan interfaces"
    logger.info("********configure_mac_v_lan function****************")
    noOfNetwroksInMacvlan=config.get(consts.KUBERNETES).get(consts.NETWORK_CREATION_IN_MACVLAN)
    #print "NEW CODE-------------------------------------------"
    #print noOfNetwroksInMacvlan
    #print "\nEXIT FROM CODE $$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n"
    for item1 in noOfNetwroksInMacvlan:
     #print "CHIRAG IN ITEM1 @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
     #print item1
     for key in item1:
            #print "\nCHIRAG ITEM1 KEY IS ---------------------------@@@\n"   
            #print key
            if key == "Multus_network":
		multus_network=item1.get("Multus_network")
                for item2 in multus_network:
                   #print "\n CHIRAG IN ITEM2%%%%%%%%%%%%%%%%%%%%%%\n"
                   #print item2
                   for key in item2:
              		#print "\n CHIRAG ITEM2 KEY in for loop"
 			#print key
  			if key == "CNI_Configuration":
				cni_configuration=item2.get("CNI_Configuration")
				for item3 in cni_configuration:
					#print "\n CHIRAG IN ITEM3"
					#print item3
	                                for key in item3:
						#print "\n CHIRAG IN ITEM3%%%%%%%%%%%%%%%%%%%"
						#print key
						if key == "Macvlan":
						       #print "\nHELLO IN MACVLAN\n"
						       macvlan_network1=item3.get("Macvlan")
				                       for macvlan_networks in macvlan_network1:
			                                 inetfaceDict=macvlan_networks.get("macvlan_networks")
			                                 macvlan_gateway=inetfaceDict.get("gateway")
			                                 macvlan_parent_interface=inetfaceDict.get("parent_interface")
			                                 macvlan_vlanid=inetfaceDict.get("vlanid")
                        			         macvlan_ip=inetfaceDict.get("ip")
			                                 macvlan_node_hostname=inetfaceDict.get("hostname")
			                                 macvlan_master=inetfaceDict.get("master")
			                                 macvlan_masterplugin=inetfaceDict.get("masterplugin")
			                                 macvlan_network_name=inetfaceDict.get("network_name")
			                                 macvlan_rangeStart=inetfaceDict.get("rangeStart")
			                                 macvlan_rangeEnd=inetfaceDict.get("rangeEnd")
			                                 macvlan_routes_dst=inetfaceDict.get("routes_dst")
			                                 macvlan_subnet=inetfaceDict.get("subnet")
			                                 macvlan_type=inetfaceDict.get("type")
			                                 print "------------------------------------------------------------------------------------------------------------------------------------------------"
			                                 print "macvlan_node_hostname :", macvlan_node_hostname
			                                 print "macvlan_parent_interface :", macvlan_parent_interface
			                                 print "macvlan_vlanid:", macvlan_vlanid
			                                 print "macvlan_ip :",macvlan_ip
			
			                                 ret=ansible_playbook_launcher.__launch_ansible_playbook_node_vlantag_interface(vlan_playbook,macvlan_node_hostname,macvlan_parent_interface,macvlan_vlanid,macvlan_ip)
			                                 if (ret==False):
			                                         logger.info('FAILED IN MACVLAN interface creation')
			               #                         exit(1)

		
 								

#    for item in noOfNetwroksInMacvlan:
#         print"in ITEM %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%" 
#         print item
#	 for key in item:
#                print "KEY is ----------------------"
#                print key
# 		if key =="MACVLAN":
#         		macvlan_network1=item.get(consts.MACVLAN)
#			for macvlan_networks in macvlan_network1:
#				  inetfaceDict=macvlan_networks.get("macvlan_networks")
#				  macvlan_gateway=inetfaceDict.get("gateway")              
#				  macvlan_parent_interface=inetfaceDict.get("parent_interface")              
#				  macvlan_vlanid=inetfaceDict.get("vlanid")              
#				  macvlan_ip=inetfaceDict.get("ip")              
#				  macvlan_node_hostname=inetfaceDict.get("hostname")            
#				  macvlan_master=inetfaceDict.get("master")                
#				  macvlan_masterplugin=inetfaceDict.get("masterplugin")    
#				  macvlan_network_name=inetfaceDict.get("network_name")    
#				  macvlan_rangeStart=inetfaceDict.get("rangeStart")        
#				  macvlan_rangeEnd=inetfaceDict.get("rangeEnd")            
#				  macvlan_routes_dst=inetfaceDict.get("routes_dst")        
#				  macvlan_subnet=inetfaceDict.get("subnet")                
#				  macvlan_type=inetfaceDict.get("type")                    
#				  print "------------------------------------------------------------------------------------------------------------------------------------------------"
#			          print "macvlan_node_hostname :", macvlan_node_hostname
#				  print "macvlan_parent_interface :", macvlan_parent_interface
#				  print "macvlan_vlanid:", macvlan_vlanid                           
#				  print "macvlan_ip :",macvlan_ip                                    
#			   
#				  ret=ansible_playbook_launcher.__launch_ansible_playbook_node_vlantag_interface(vlan_playbook,macvlan_node_hostname,macvlan_parent_interface,macvlan_vlanid,macvlan_ip) 
#				  if (ret==False):
#					  logger.info('FAILED IN MACVLAN interface creation')
#		#			  exit(1) 
#
			   

  return ret

  
  
  
  
def removal_macvlan_interface(config):    #function for mac-vlan interface removal
  """
  This method is used for create macvlan network after multus
  :param config :input configuration file
  :return ret :t/f
  """
  ret = False
  if config:
    vlan_removal_playbook=consts.K8_VLAN_INTERFACE_REMOVAL_PATH
    print "Removal_mac_vlan interfaces"
    logger.info("********Removal_mac_v_lan function****************")
    noOfNetwroksInMacvlan=config.get(consts.KUBERNETES).get(consts.NETWORK_CREATION_IN_MACVLAN)
    #print "NEW CODE-------------------------------------------"
    #print noOfNetwroksInMacvlan
    #print "\nEXIT FROM CODE $$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n"
    for item1 in noOfNetwroksInMacvlan:
     #print "CHIRAG IN ITEM1 @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
     #print item1
     for key in item1:
            #print "\nCHIRAG ITEM1 KEY IS ---------------------------@@@\n"
            #print key
            if key == "Multus_network":
                multus_network=item1.get("Multus_network")
                for item2 in multus_network:
                   #print "\n CHIRAG IN ITEM2%%%%%%%%%%%%%%%%%%%%%%\n"
                   #print item2
                   for key in item2:
                        #print "\n CHIRAG ITEM2 KEY in for loop"
                        #print key
                        if key == "CNI_Configuration":
                                cni_configuration=item2.get("CNI_Configuration")
                                for item3 in cni_configuration:
                                        #print "\n CHIRAG IN ITEM3"
                                        #print item3
                                        for key in item3:
                                                #print "\n CHIRAG IN ITEM3%%%%%%%%%%%%%%%%%%%"
                                                #print key
                                                if key == "Macvlan":
                                                       #print "\nHELLO IN MACVLAN\n"
                                                       macvlan_network1=item3.get("Macvlan")
                                                       for macvlan_networks in macvlan_network1:
			                                          inetfaceDict=macvlan_networks.get("macvlan_networks")
					         		  macvlan_gateway=inetfaceDict.get("gateway")              
								  macvlan_parent_interface=inetfaceDict.get("parent_interface")              
								  macvlan_vlanid=inetfaceDict.get("vlanid")              
								  macvlan_ip=inetfaceDict.get("ip")              
								  macvlan_node_hostname=inetfaceDict.get("hostname")            
								  macvlan_master=inetfaceDict.get("master")                
								  macvlan_masterplugin=inetfaceDict.get("masterplugin")    
								  macvlan_network_name=inetfaceDict.get("network_name")    
								  macvlan_rangeStart=inetfaceDict.get("rangeStart")        
								  macvlan_rangeEnd=inetfaceDict.get("rangeEnd")            
								  macvlan_routes_dst=inetfaceDict.get("routes_dst")        
								  macvlan_subnet=inetfaceDict.get("subnet")                
								  macvlan_type=inetfaceDict.get("type")                    
								  print "------------------------------------------------------------------------------------------------------------------------------------------------"
							          print "macvlan_node_hostname :", macvlan_node_hostname
								  print "macvlan_parent_interface :", macvlan_parent_interface
								  print "macvlan_vlanid:", macvlan_vlanid                           
								  print "macvlan_ip :",macvlan_ip                                    
							   
								  ret=ansible_playbook_launcher.__launch_ansible_playbook_node_vlantag_interface_removal(vlan_removal_playbook,macvlan_node_hostname,macvlan_parent_interface,macvlan_vlanid) 
								  if (ret==False):
									  logger.info('FAILED IN MACVLAN interface removal')
									  exit(1) 
							   
				
    return ret
  
def macvlan_cleanup(config):
   logger.info("***********************MACVLAN PLUGIN REMOVAL**************************")
    
   #multus_cni_installed= True
   logger.info("***********************Additioanl N/W plugins**************")
   logger.info("***********************multus_cni**************************")
   macvlan_cni = False
   macvlan_cni = get_macvlan_value(config)
   print 'macvlan value n macvlan_cleanup function:',macvlan_cni
   if(macvlan_cni== True):
		logger.info('REMOVING MACVLAN')
		ret = removal_macvlan_interface(config)
                noOfhosts_fornetwork=config.get(consts.KUBERNETES).get("node_configuration")
                for macvlan_host_fornetwork in noOfhosts_fornetwork:
                                if macvlan_host_fornetwork != None:
                                         inetfaceDict_fornetwork=macvlan_host_fornetwork.get("host")
                                         print "--------------------------------------------------------------"
                                         hostname_fornetwork=inetfaceDict_fornetwork.get("hostname")
                                         node_type_fornetwork=inetfaceDict_fornetwork.get("node_type")
                                         #print hostname_fornetwork
                                         #print node_type_fornetwork
                                         if (node_type_fornetwork=="master"):
                                           print "inside master for cleanup\n"
                                           ret = remove_macvlan_networks(config,hostname_fornetwork)

   else:
       	    logger.info('MAC-VLAN CONFIGURATION  EXIT , REASON--> MACVLAN  IS DISABLED ')
	    ret=False
   return ret 

def macvlan_removal_node(config):
   logger.info("***********************MACVLAN PLUGIN REMOVAL**************************")

   logger.info("***********************Additioanl N/W plugins**************")
   logger.info("***********************multus_cni**************************")
   macvlan_cni = False
   macvlan_cni = get_macvlan_value(config)
   print 'macvlan value n macvlan_removal node function:',macvlan_cni
   if(macvlan_cni== True):
                logger.info('REMOVING MACVLAN')
                ret = removal_macvlan_interface(config)
                Project_name=config.get(consts.KUBERNETES).get(consts.PROJECT_NAME)
                master_node_macvlan = ansible_configuration.get_host_master_name(Project_name)
                ret = remove_macvlan_networks(config,master_node_macvlan)

   else:
            logger.info('MAC-VLAN CONFIGURATION  EXIT , REASON--> MACVLAN  IS DISABLED ')
            ret=False
   return ret


def macvlan_creation_node(config,multus_cni_installed):
                  logger.info("***********************MACVLAN FOR DYNAMIC NODE ADDITION**************************")    
		  print "multus_cni_installed ",multus_cni_installed
		  macvlan_cni = False
		  macvlan_cni = get_macvlan_value(config)
		  print 'macvlan value n macvlan creation node function:',macvlan_cni
		  if(multus_cni_installed == True):
			if(macvlan_cni== True):
					logger.info('CONFIGURING MAC-VLAN')
                                        Project_name=config.get(consts.KUBERNETES).get(consts.PROJECT_NAME)
                                        master_node_macvlan = ansible_configuration.get_host_master_name(Project_name)
					ret = configure_macvlan_interface(config)
					ret = configure_macvlan_networks(config,master_node_macvlan)

			else:
				  logger.info('MAC-VLAN CONFIGURATION  EXIT , REASON--> MACVLAN  IS DISABLED ')
				  ret=False
	                return ret			  



def macvlan_installtion(config):
                                     logger.info('CONFIGURING MAC-VLAN')
                                     ret = configure_macvlan_interface(config)
                                     #ret = configure_macvlan_networks(config)
                                     noOfhosts_fornetwork=config.get(consts.KUBERNETES).get(consts.HOSTS)
                                     for macvlan_host_fornetwork in noOfhosts_fornetwork:
                                                        if macvlan_host_fornetwork != None:
                                                                 inetfaceDict_fornetwork=macvlan_host_fornetwork.get("host")
                                                                 print "--------------------------------------------------------------"
                                                                 hostname_fornetwork=inetfaceDict_fornetwork.get("hostname")
                                                                 node_type_fornetwork=inetfaceDict_fornetwork.get("node_type")
                                                                 #print hostname_fornetwork
                                                                 #print node_type_fornetwork
                                                                 if (node_type_fornetwork=="master"):
                                                                   #print "inside master\n"
                                                                   ret = configure_macvlan_networks(config,hostname_fornetwork)
	                             return ret
                                       
 


def dhcp_installtion(config):
                                     logger.info('CONFIGURING DHCP')
                                     noOfhosts_fornetwork=config.get(consts.KUBERNETES).get(consts.HOSTS)
                                     for dhcp_host_fornetwork in noOfhosts_fornetwork:
                                                        if dhcp_host_fornetwork != None:
                                                                 inetfaceDict_fornetwork=dhcp_host_fornetwork.get("host")
                                                                 print "--------------------------------------------------------------"
                                                                 hostname_fornetwork=inetfaceDict_fornetwork.get("hostname")
                                                                 node_type_fornetwork=inetfaceDict_fornetwork.get("node_type")
                                                                 #print hostname_fornetwork
                                                                 #print node_type_fornetwork
                                                                 if (node_type_fornetwork=="minion"):
                                                                   #print "inside master\n"
                                                                   #ret = configure_dhcp_plugin(config,hostname_fornetwork)
                                                                   macvlan_dhcp_daemon_playbook=consts.K8_DHCP_PATH
                                                                   print "DHCP DAEMON RUNNING"
                                                                   ret = ansible_playbook_launcher.__launch_ansible_playbook__dhcp_daemon_creation(macvlan_dhcp_daemon_playbook,hostname_fornetwork)
								   if (ret==False):
									    logger.info('FAILED IN DHCP DAEMON installation')



                                     return ret


 
#########get master ip############ 
def get_master_ip(Project_name):
 import file_utils
 VARIABLE_FILE=consts.VARIABLE_FILE
 config=file_utils.read_yaml(VARIABLE_FILE)
 project_path=config.get(consts.PROJECT_PATH)
 inventory_file_path = project_path+Project_name+"/inventory.cfg" 
 print "************Inventory file in get_master_ip function **********************"
 print inventory_file_path

 with open(inventory_file_path) as f:
    for line in f:
        if re.match("\[kube\-master\]", line):
           master_hostname1=f.next()
           master_hostname=master_hostname1.strip(' \t\n\r')
           print "************master host name**********************"
           print master_hostname

 with open(inventory_file_path) as f:
      for line in f:
        if "ansible_ssh_host=" in line:
           host_ip1=line.split("ansible_ssh_host=",1)[1]
           host_ip=host_ip1.strip(' \t\n\r')
	   hostnamestringlist = line.split(" ")
           host_name=hostnamestringlist[0]
           host_name=host_name.strip(' \t\n\r')
           if host_ip:
              print host_name
              print master_hostname
              if (host_name == master_hostname):
                 master_ip = host_ip 
 return master_ip

#########clean up flannel interfaces############ 
def clean_up_flannel(hostname_map,host_node_type_map,networking_plugin,config,Project_name):
 """
 This function is used to clean the flannel additional plugin
 """
 ret = False
 if config:
   if(networking_plugin != "flannel"):
     networks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
     multus_network = get_multus_network(networks).get("Multus_network")
     multus_cni=get_multus_network_elements(multus_network, "CNI")
     multus_cni_configuration=get_multus_network_elements(multus_network, "CNI_Configuration")
     if(None != multus_cni):
       logger.info("***********************multus_cni and additional plugins clean up**************************")
       hosts_data_dict=get_flannel_nw_data(config)
       for cni in multus_cni:
         if(consts.FLANNEL == cni):
           ret = ansible_configuration.delete_flannel_interfaces(hostname_map,host_node_type_map,hosts_data_dict,Project_name)
           if(ret!=True):
              logger.info('FAILED IN FLANNEL INTERFACE DELETION')
     else:
       ret = True
   else:
     logger.info('FLANNEL IS DEFAULT PLUGIN')
     ret = True 
   
   return ret

#########get_flannel_nw_data############
def get_flannel_nw_data(config):
 """
 This function is used for get the flannel network info
 """

 hosts_data_dict=config.get(consts.KUBERNETES).get(consts.NETWORKS)
 return hosts_data_dict
  
#########get multus cni value############
def get_multus_cni_value(config):
 """
 This function is used to get multus cni value
 """
 ret = False
 sriov_cni = False
 flannel_cni = False
 weave_cni = False
 macvlan_cni = False
 noOfNetworks=config.get(consts.KUBERNETES).get(consts.NETWORKS)
 #print noOfNetworks
 for item1 in noOfNetworks:
  for key in item1:
    if(key == "Multus_network"):
      multus_network=item1.get("Multus_network")
      for item2 in multus_network:
        for key in item2:
          if(key == "CNI"):
             multus_cni=item2.get("CNI")
             if(None != multus_cni):
              for cni in multus_cni:
                #print cni
                if("sriov" == cni):
                  sriov_cni = True
                elif(consts.FLANNEL == cni):
                  flannel_cni = True
                elif(consts.WEAVE == cni):
                  weave_cni = True
                elif("macvlan" == cni):
                  macvlan_cni = True

  if(True == sriov_cni or True == flannel_cni or True == weave_cni or True == macvlan_cni):
      ret = True

 return ret
        
#########create default network###########
def create_default_network_multus(config,hostname_map,host_node_type_map,service_subnet,pod_subnet,networking_plugin):
 """
 This function is used to create default network
 """
 ret = False
 noOfNetworks=config.get(consts.KUBERNETES).get(consts.NETWORKS)
 if(networking_plugin == "weave" or networking_plugin == "flannel"):
   for item1 in noOfNetworks:
     for key in item1:
       if(key == "Default_Network"):
           default_network=item1.get(consts.DEFAULT_NETWORK)
           if(None != default_network):
              ret = ansible_configuration.create_default_network(hostname_map,host_node_type_map,service_subnet,pod_subnet,networking_plugin,default_network)

 return ret
                    
#########create flannel interafce############
def launch_flannel_interface(config,hostname_map,host_node_type_map,networking_plugin,Project_name):
 """
 This function is used to create flannel interface
 """
 ret = False
 flannel_nw_name_list=[]
 if(networking_plugin != "flannel"):
   hosts_data_dict=get_flannel_nw_data(config)
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
                              ret = ansible_configuration.create_flannel_interface(hostname_map,host_node_type_map,networking_plugin,Project_name,hosts_data_dict)
 else:
   logger.info('FLANNEL IS ALREADY CONFIGURED')

 return ret
                    
#########create weave interafce############
def launch_weave_interface(config,hostname_map,host_node_type_map,service_subnet,pod_subnet,networking_plugin):
 """
 This function is used to create weave interface
 """
 ret = False
 if(networking_plugin != "weave"):
     weaveNetworkList_map=__noOfNetworkInWeave_list(config) 
     print weaveNetworkList_map
     for item in weaveNetworkList_map:
          for key in item:
            print item
            if(consts.WEAVE_NETWORK == key):
               weave_network=item.get(consts.WEAVE_NETWORK)
               print weave_network
               for item1 in weave_network:
                  print item1
                  ret = ansible_configuration.create_weave_interface(hostname_map,host_node_type_map,service_subnet,pod_subnet,networking_plugin,item1)
 else:
   logger.info('WEAVE IS ALREADY CONFIGURED')

 return ret

#########get macvlan value############
def get_macvlan_value(config):
 """
 This function is used to get multus cni value
 """
 ret = False
 noOfNetworks=config.get(consts.KUBERNETES).get(consts.NETWORKS)
 #print noOfNetworks
 for item1 in noOfNetworks:
  for key in item1:
    if(key == "Multus_network"):
      multus_network=item1.get("Multus_network")
      for item2 in multus_network:
        for key in item2:
          if(key == "CNI"):
             multus_cni=item2.get("CNI")
             if(None != multus_cni):
              for cni in multus_cni:
                #print cni
                if("macvlan" == cni):
                  ret = True

 return ret


#########get dhcp value############
def get_dhcp_value(config):
 """
 This function is used to get multus cni value
 """
 ret = False
 noOfNetworks=config.get(consts.KUBERNETES).get(consts.NETWORKS)
 #print noOfNetworks
 for item1 in noOfNetworks:
  for key in item1:
    if(key == "Multus_network"):
      multus_network=item1.get("Multus_network")
      for item2 in multus_network:
        for key in item2:
          if(key == "CNI"):
             multus_cni=item2.get("CNI")
             if(None != multus_cni):
              for cni in multus_cni:
                #print cni
                if("dhcp" == cni):
                  ret = True

 return ret

#########get flannel cni value############ 
def get_flannel_value(config):
 """
 This function is used to get multus cni value
 """
 ret = False
 noOfNetworks=config.get(consts.KUBERNETES).get(consts.NETWORKS)
 #print noOfNetworks
 for item1 in noOfNetworks:
  for key in item1:
    if(key == "Multus_network"):
      multus_network=item1.get("Multus_network")
      for item2 in multus_network:
        for key in item2:
          if(key == "CNI"):
             multus_cni=item2.get("CNI")
             if(None != multus_cni):
              for cni in multus_cni:
                #print cni
                if("flannel" == cni):
                  ret = True

 return ret

#########clean up weave############ 
def clean_up_weave(hostname_map,host_node_type_map,networking_plugin,config,Project_name):
 """
 This function is used to clean the weave additional plugin
 """
 ret = False
 if config:
   if(networking_plugin != "weave"):
     networks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
     hosts_data_dict=get_weave_nw_data(config)
     multus_network = get_multus_network(networks).get("Multus_network")
     multus_cni=get_multus_network_elements(multus_network, "CNI")
     multus_cni_configuration=get_multus_network_elements(multus_network, "CNI_Configuration")
     if(None != multus_cni):
       logger.info("***********************multus_cni and additional plugins clean up**************************")
       for cni in multus_cni:
         if(consts.WEAVE == cni):
           ret = ansible_configuration.delete_weave_interface(hostname_map,host_node_type_map,hosts_data_dict,Project_name)
           if(ret!=True):
              logger.info('FAILED IN WEAVE INTERFACE DELETION')
     else:
       ret = True
   else:
     logger.info('WEAVE IS DEFAULT PLUGIN')
     hosts_data_dict=get_weave_nw_data(config)
     ret = ansible_configuration.delete_default_weave_interface(hostname_map,host_node_type_map,hosts_data_dict,Project_name)
     if(ret!=True):
        logger.info('FAILED IN WEAVE INTERFACE DELETION')

   return ret

#########get_weave_nw_data############
def get_weave_nw_data(config):
 """
 This function is used for get the weave network info
 """

 hosts_data_dict=config.get(consts.KUBERNETES).get(consts.NETWORKS)
 return hosts_data_dict

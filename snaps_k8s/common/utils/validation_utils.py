######################################################################
# ARICENT - validation_utils.py
#
# Copyright (C) 2017 Aricent Inc . All Rights Reserved.
#
# File Name: validation_utils.py
#
# File Description: This script is responsible for deploying
#                Aricent_Iaas environments and Kubernetes Services
#
# Revised: 30 may 2018
#
######################################################################

# validation_utils.py
import subprocess
import logging
import string
import re
from snaps_k8s.common.consts import consts

logger = logging.getLogger('validation_utils')


def validate_deployment_file(config):
    '''
    Calls all the validations
    '''
    logger.info("validate_deployment_file function")
    index = 1

    if not validate_kubernetes_tag(config):
        exit(1)
    if not validate_kubernetes_params(config):
        exit(1)
    if not validate_node_config_tag(config):
        exit(1)
    if not validate_node_config_params(config):
        exit(1)
    if not validate_count_master_minion(config):
        exit(1)
    if not validate_ha_config(config):
        pass
    else:
        if not validate_api_ext_loadbalancer_tag_params(config):
            exit(1)
        if not validate_countmasters(config):
            exit(1)
    if not validate_access_and_security_tag(config):
        pass
    else:
        if not validate_access_and_security_params(config):
            exit(1)

    if not validate_docker_repo_tag(config):
        exit(1)
    if not validate_docker_repo_params(config):
        exit(1)
    if not validate_proxies__tag(config):
        pass
    else:
        if not validate_proxy__params(config):
            exit(1)

    if not validate_network__tag(config):
        exit(1)
    if not validate_default_network__params(config):
        exit(1)
    if not validate_multus_network_tag(config):
        return True
    else:
        if not validate_multus_network_cni(config, index):
            exit(1)
        if not validate_multus_network_cni_conf(config, index):
            exit(1)
        if not validate_cni_params(config):
            exit(1)
        if not validate_duplicatein_cni_and_networkplugin(config):
            exit(1)
        if not ismaster_count_for_deployment(config):
            exit(1)

    if not validate_ceph_vol_tag(config):
        if not validate_nodetype_data(config):
            exit(1)
        if not validate_ceph_vol_params(config):
            exit(1)
        if not validate_ceph_controller_params(config):
            exit(1)
        if not validate_ceph_osd__params(config):
            exit(1)
    logger.info('Deployment file is valid')


def validate_kubernetes_tag(config):
    '''
    Checks the presence of Kubernetes tag
    '''
    logger.info("checking kubernetes tag")
    if validate_dict_data(config, consts.KUBERNETES):
        return True
    else:
        return False


def validate_kubernetes_params(config):
    '''
    Checks the presence of Kubernetes parameters
    '''
    logger.info("checking kubernetes params")

    all_data_dictforkubernetesparams = config.get("kubernetes")
    if not validate_dict_data(all_data_dictforkubernetesparams,
                              consts.PROJECT_NAME):
        return False
    if not validate_dict_data(all_data_dictforkubernetesparams,
                              consts.GIT_BRANCH):
        return False
    if not validate_dict_data(all_data_dictforkubernetesparams,
                              consts.METRICS_SERVER):
        return False
    if not validate_dict_data(all_data_dictforkubernetesparams,
                              consts.HOSTS):
        return False
    if not validate_dict_data(all_data_dictforkubernetesparams,
                              consts.DOCKER_REPO):
        return False
    if not validate_dict_data(all_data_dictforkubernetesparams,
                              consts.NETWORKS):
        return False
    if not validate_dict_data(all_data_dictforkubernetesparams,
                              consts.PERSISTENT_VOLUME):
        return False
    if validate_dict_data2(all_data_dictforkubernetesparams,
                           "Exclusive_CPU_alloc_support"):
        if not (all_data_dictforkubernetesparams['Exclusive_CPU_alloc_support']
                or not
            all_data_dictforkubernetesparams['Exclusive_CPU_alloc_support']):
            logger.error("Value of Exclusive_CPU_alloc_support "
                         "should be either true or false")
            return False
    return True


def validate_ha_config(config):
    logger.info("checking ha_config_tag")
    all_data_dictforkubernetesparams = config.get("kubernetes")
    if validate_dict_data2(all_data_dictforkubernetesparams,
                           "ha_configuration"):
        return True
    return False


def validate_api_ext_loadbalancer_tag_params(config):
    logger.info("checking api_ext_loadbalancer_tag")
    all_data_dictforkubernetesparams = config.get("kubernetes")
    all_data_dict_for_node_configurationparams = config.get("kubernetes"). \
        get("node_configuration")
    all_data_dict_for_ha_params = config.get("kubernetes"). \
        get("ha_configuration")
    if validate_dict_data2(all_data_dictforkubernetesparams,
                           "ha_configuration"):
        if validate_dict_data(all_data_dict_for_ha_params[0],
                              "api_ext_loadbalancer"):
            if validate_dict_data(all_data_dict_for_ha_params[0].
                                          get("api_ext_loadbalancer"), "ip"):
                if validate_dict_data(
                        all_data_dict_for_node_configurationparams[0], "host"):
                    for all_data_for_host in \
                            all_data_dict_for_node_configurationparams:
                        if all_data_for_host.get("host")[consts.IP] == \
                                all_data_dict_for_ha_params[0].get(
                                    "api_ext_loadbalancer")['ip']:
                            logger.error("bootstrap ip should never match "
                                         "with the master or node")
                            return False
            else:
                return False
            if not validate_dict_data(all_data_dict_for_ha_params[0].
                                              get("api_ext_loadbalancer"),
                                      "user"):
                return False
            if not validate_dict_data(all_data_dict_for_ha_params[0].
                                              get("api_ext_loadbalancer"),
                                      "password"):
                return False
            if validate_dict_data(all_data_dict_for_ha_params[0].
                                          get("api_ext_loadbalancer"), "port"):
                if all_data_dict_for_ha_params[0]. \
                        get("api_ext_loadbalancer")['port'] == "" or \
                                all_data_dict_for_ha_params[0]. \
                                        get("api_ext_loadbalancer")[
                                    'port'] == 6443:
                    logger.error("Port shloud not be empty or 6443")
                    return False
            else:
                return False
        else:
            return False
    return True


def validate_count_master_minion(config):
    logger.info("checking count master and minion")
    countformaster = 0
    countforminion = 0
    all_data_dict_for_node_configuration_params = config.get("kubernetes").get(
        "node_configuration")
    if validate_dict_data(all_data_dict_for_node_configuration_params[0],
                          "host"):
        for all_data_for_host in all_data_dict_for_node_configuration_params:
            if all_data_for_host.get("host")[consts.NODE_TYPE] == "master":
                countformaster = countformaster + 1
            if all_data_for_host.get("host")[consts.NODE_TYPE] == "minion":
                countforminion = countforminion + 1
        if countforminion > 0:
            pass
        else:
            logger.error("Atleast one minion is required")
            return False
        if countformaster > 0:
            pass
        else:
            logger.error("Atleast master is required")
            return False

    return True


def validate_countmasters(config):
    logger.info("checking Count the no of masters")
    count = 0
    all_data_dict_for_node_configuration_params = config.get("kubernetes").get(
        "node_configuration")
    if validate_dict_data(all_data_dict_for_node_configuration_params[0],
                          "host"):
        for all_data_for_host in all_data_dict_for_node_configuration_params:
            if all_data_for_host.get("host")[consts.NODE_TYPE] == "master":
                count = count + 1
        if count % 2 and count > 1:
            return True
        logger.error(
            "Number of masters for HA should be odd and greater than one")
        return False
    return False


def validate_access_and_security_tag(config):
    '''
    Checks the presence of basic_authentication tag
    '''
    logger.info("checking access_and_security tag")

    all_data_dict_for_kubernetesparams = config.get("kubernetes")
    if not validate_dict_data(all_data_dict_for_kubernetesparams,
                              "access_and_security"):
        return False
    return True


def validate_access_and_security_params(config):
    '''
    Checks the presence of access_and_security parameters
    '''
    logger.info("checking basic_authentication params")

    all_data_dict_for_access_and_security_params = config.get(
        "kubernetes").get("access_and_security")
    if "authentication" in all_data_dict_for_access_and_security_params:
        if "basic_authentication" not in \
            all_data_dict_for_access_and_security_params.get("authentication") \
            or "token_authentication" not in \
                all_data_dict_for_access_and_security_params.get("authentication"):
            logger.error(
                "Atleast one out of basic_authentication or "
                "token_authentication must be present")
            return False
        else:
            return True
    else:
        logger.error("authentication is not present")
        return False
    return True


def validate_node_config_tag(config):
    '''
    Checks the presence of node configuration tag
    '''
    logger.info("checking node config tag")
    all_data_dictfor_kubernetes_params = config.get("kubernetes")
    if not validate_dict_data(all_data_dictfor_kubernetes_params,
                              consts.HOSTS):
        return False
    return True


def validate_node_config_params(config):
    '''
    Checks the presence of node configuration parameters
    '''
    logger.info("checking node configuration params")

    all_data_dict_for_node_configuration_params = config.get("kubernetes").get(
        "node_configuration")
    if validate_dict_data(all_data_dict_for_node_configuration_params[0],
                          "host"):
        for all_data_for_host in all_data_dict_for_node_configuration_params:
            if not validate_dict_data(all_data_for_host.get("host"),
                                      consts.HOST_NAME):
                return False
            if not validate_dict_data(all_data_for_host.get("host"),
                                      consts.IP):
                return False
            if not validate_dict_data(all_data_for_host.get("host"),
                                      consts.NODE_TYPE):
                return False
            if not validate_dict_data(all_data_for_host.get("host"),
                                      consts.LABEL_KEY):
                return False
            if not validate_dict_data(all_data_for_host.get("host"),
                                      consts.LABEL_VALUE):
                return False
            if not validate_dict_data(all_data_for_host.get("host"),
                                      "registry_port"):
                return False
            else:
                if not (all_data_for_host.get("host")[
                            consts.NODE_TYPE] == 'master' or
                                'minion' == all_data_for_host.get("host")[
                                consts.NODE_TYPE]):
                    logger.error("Node type should be either master or minion")
                    return False
            if not validate_dict_data(all_data_for_host.get("host"),
                                      consts.PASSWORD):
                return False
            if not validate_dict_data(all_data_for_host.get("host"), "user"):
                return False
    else:
        logger.error("host not present")
        return False
    return True


def validate_docker_repo_tag(config):
    '''
    Checks the presence of docker repo tag
    '''
    logger.info("checking docker repo tag")

    all_data_dict_for_kubernetes_params = config.get("kubernetes")
    if not validate_dict_data(all_data_dict_for_kubernetes_params,
                              consts.DOCKER_REPO):
        return False
    return True


def validate_docker_repo_params(config):
    '''
    Checks the presence of docker repo parameters
    '''
    logger.info("checking docker repo  params")
    all_data_dict_for_docker_repo_params = config.get("kubernetes").get(
        "Docker_Repo")
    if not validate_dict_data(all_data_dict_for_docker_repo_params, consts.IP):
        return False
    if not validate_dict_data(all_data_dict_for_docker_repo_params,
                              consts.PASSWORD):
        return False
    if not validate_dict_data(all_data_dict_for_docker_repo_params, "user"):
        return False
    if not validate_dict_data(all_data_dict_for_docker_repo_params,
                              consts.PORT):
        return False
    return True


def validate_proxies__tag(config):
    '''
    Checks the presence of proxies tag
    '''
    logger.info("checking proxies tag")

    all_data_dict_for_kubernetes_params = config.get("kubernetes")
    if not validate_dict_data(all_data_dict_for_kubernetes_params,
                              consts.PROXIES):
        return False
    return True


def validate_proxy__params(config):
    '''
    Checks the presence of proxy parameters
    '''
    logger.info("checking proxy  params")
    all_data_dict_for_proxy_params = config.get("kubernetes").get("proxies")

    if consts.HTTP_PROXY in all_data_dict_for_proxy_params:
        pass
    else:
        logger.error("HTTP proxy tag is mandatory")
        return False
    if consts.HTTPS_PROXY in all_data_dict_for_proxy_params:
        pass
    else:
        logger.error("HTTPS proxy tag is mandatory")
        return False
    if consts.NO_PROXY in all_data_dict_for_proxy_params:
        pass
    else:
        logger.error("No proxy tag is mandatory")
        return False
    return True


def validate_network__tag(config):
    '''
    Checks the presence of network tag
    '''
    logger.info("checking networks tag")

    all_data_dict_for_kubernetes_params = config.get("kubernetes")
    if not validate_dict_data(all_data_dict_for_kubernetes_params,
                              consts.NETWORKS):
        return False
    return True


def validate_default_network__params(config):
    '''
    Checks the presence of default network tag and its parameters
    '''
    logger.info("checking def networks  params")
    all_data_dict_for_net_params = config.get("kubernetes").get("Networks")
    if validate_dict_data(all_data_dict_for_net_params[0],
                          consts.DEFAULT_NETWORK):
        if not validate_dict_data(all_data_dict_for_net_params[0].values()[0],
                                  consts.NETWORKING_PLUGIN):
            return False
        else:
            if all_data_dict_for_net_params[0].values()[0][
                'networking_plugin']:
                if not validate_dict_data(
                        all_data_dict_for_net_params[0].values()[0],
                        "isMaster"):
                    return False
        if not validate_dict_data(all_data_dict_for_net_params[0].values()[0],
                                  consts.SERVICE_SUBNET):
            return False
        if not validate_dict_data(all_data_dict_for_net_params[0].values()[0],
                                  consts.POD_SUBNET):
            return False
        if not validate_dict_data(all_data_dict_for_net_params[0].values()[0],
                                  consts.NETWORK_NAME):
            return False
    else:
        logger.error("def network not present")
        return False
    return True


def validate_multus_network_tag(config):
    '''
    Checks the presence of multus network tag
    '''
    logger.info("checking multus networks tag ")
    all_data_dict_for_net_params = config.get("kubernetes").get("Networks")
    count = 0
    for element in all_data_dict_for_net_params:
        count = count + 1
    if count > 1:
        if 'Multus_network' in all_data_dict_for_net_params[1]:
            return True
        else:
            return False
    return False


def validate_multus_network_tag_network_yaml(config):
    '''
    Checks the presence of multus network tag for network yaml
    '''
    logger.info("checking multus networks tag ")
    all_data_dict_for_net_params = config.get("kubernetes").get("Networks")

    if 'Multus_network' in all_data_dict_for_net_params[0]:
        return True
    return False


def validate_multus_network_cni(config, index):
    '''
    Checks the presence of CNI tag in Multus network and also checks
    presence of multus network tag
    '''
    logger.info("checking multus networks CNI ")
    all_data_dict_for_net_params = config.get("kubernetes").get("Networks")
    list_for_multus_network_params_data = []

    if validate_dict_data(all_data_dict_for_net_params[index],
                          "Multus_network"):
        list_for_multus_network_params_data = \
            all_data_dict_for_net_params[index]['Multus_network']
        key_to_append_multus_network_params = []
        for element in list_for_multus_network_params_data:
            key_to_append_multus_network_params.append(element.keys())

        if ['CNI'] in key_to_append_multus_network_params:
            return True
        else:
            logger.error("CNI does not exist")
            return False
    else:
        logger.error("Multus network does not exist")
        return False


def validate_multus_network_cni_conf(config, index):
    '''
    Checks the presence of CNI Configuration tag in Multus network
    and also checks presence of multus network tag
    '''
    logger.info("checking multus networks CNI CONF tag")
    all_data_dict_for_net_params = config.get("kubernetes").get("Networks")
    list_for_multus_network_params_data = []
    if validate_dict_data(all_data_dict_for_net_params[index],
                          "Multus_network"):
        list_for_multus_network_params_data = \
            all_data_dict_for_net_params[index]['Multus_network']
        key_to_append_multus_network_params = []
        for element in list_for_multus_network_params_data:
            key_to_append_multus_network_params.append(element.keys())
        if ['CNI_Configuration'] not in key_to_append_multus_network_params:
            logger.error("CNIconfig does not exist")
            return False
    return True


def validate_cni_params(config):
    '''
    Checks the presence of atleast one plugin in Cni tag
    '''
    index = 1
    logger.info("checking multus networks  params")
    all_data_dict_for_net_params = config.get("kubernetes").get("Networks")
    list_for_cni_params = []
    item_weave = consts.WEAVE
    item_flannel = consts.FLANNEL
    item_sriov = "sriov"
    item_macvlan = "macvlan"
    val = ""
    for all_keys in all_data_dict_for_net_params[1]:
        for keys_in_all_keys in all_data_dict_for_net_params[1][all_keys]:
            list_for_cni_params.append(keys_in_all_keys)
            break

    for item in list_for_cni_params:
        val = item.get('CNI')

    if val is not None:
        if item_weave in list_for_cni_params[0].get("CNI"):
            if not validate_multus_network_weave_params(config):
                logger.error("Weave network parameters are wrong")
                return False
            if not validate_masterflag_for_weave(config):
                logger.error("master flag is true in weave ")
                return False

        if item_flannel in list_for_cni_params[0].get("CNI"):
            if not validate_multus_network_flannelnet__params(config):
                logger.error("flannel network parameters are wrong")
                return False
            if not validate_masterflag_for_flannel(config):
                logger.error("master flag is true in flannel")
                return False

        if item_sriov in list_for_cni_params[0].get("CNI"):
            if not validate_multus_network_sriov__params(config, index):
                logger.error("sriov network parameters are wrong ")
                return False
            if not validate_masterflag_for_sriov(config):
                logger.error("master flag is true in sriov")
                return False
            if not validate_dhcpmandatory(config, index):
                logger.error("dhcp mandatory in cni if dhcp in sriov")
                return False

        if item_macvlan in list_for_cni_params[0].get("CNI"):
            if not validate_multus_network_macvlan__params(config, index):
                logger.error("macvlan network parameters are wrong ")
                return False
            if not validate_masterflag_for_macvlan(config):
                logger.error("master flag is true in macvlan ")
                return False
            if not validate_dhcpmandatory(config, index):
                logger.error("dhcp mandatory in cni if dhcp in macvlan")
                return False

    return True


def validate_duplicatein_cni_and_networkplugin(config):
    '''
    Checks if there exists the same plugin in both default network
    plugin tag and in Cni parameters
    '''
    logger.info("checking duplicate values")
    all_data_dict_for_net_params = config.get("kubernetes").get("Networks")
    networkpluginvalue = all_data_dict_for_net_params[0].values()[0][
        'networking_plugin']

    list_for_cni_params = []
    item_weave = consts.WEAVE
    item_flannel = consts.FLANNEL
    item_sriov = "sriov"
    item_macvlan = "macvlan"
    val = ""

    for all_keys in all_data_dict_for_net_params[1]:
        for keys_in_all_keys in all_data_dict_for_net_params[1][all_keys]:
            list_for_cni_params.append(keys_in_all_keys)
            break

    for item in list_for_cni_params:
        val = item.get('CNI')

    if val is not None:
        if item_weave in list_for_cni_params[0].get(
                "CNI") and item_weave == networkpluginvalue:
            logger.error("duplicate weave")
            return False
        if item_flannel in list_for_cni_params[0].get(
                "CNI") and item_flannel == networkpluginvalue:
            logger.error("duplicate flannel")
            return False
        if item_sriov in list_for_cni_params[0].get(
                "CNI") and item_sriov == networkpluginvalue:
            logger.error("duplicate Sriov")
            return False
        if item_macvlan in list_for_cni_params[0].get(
                "CNI") and item_macvlan == networkpluginvalue:
            logger.error("duplicate macvlan")
            return False
    return True


def validate_multus_network_flannelnet__params(config):
    '''
    Checks the presence of Flannel network parameters
    '''
    logger.info("checking flannelnet params")
    all_data_dict_for_net_params = config.get("kubernetes").get("Networks")

    keysofallnetworks = []
    flag = False
    for all_keys in all_data_dict_for_net_params[1]:
        for keys_in_all_keys in all_data_dict_for_net_params[1][all_keys]:
            cni_config_data = keys_in_all_keys.get("CNI_Configuration")
        for element in cni_config_data:
            for all_keys in element:
                keysofallnetworks.extend(element.values()[0])
    counter = 0
    for element in keysofallnetworks:
        if 'flannel_network' in element:
            counter = counter + 1
    if counter > 0:
        pass
    else:
        logger.error("flannel_network should be present atleast once")
        return False
    for element in keysofallnetworks:
        if 'flannel_network' in element:
            if "isMaster" in element.get("flannel_network"):
                pass
            else:
                logger.error("isMaster Flag is absent in flannel network")
                return False

            flag = True
            if validate_dict_data(element['flannel_network'],
                                  "network_name") and \
                    validate_dict_data(element['flannel_network'],
                                       "network") and \
                    validate_dict_data(element['flannel_network'], "subnet"):
                return True
            else:
                return False
        else:
            logger.error("flannel network does not exist")
            return False
    if not flag:
        return False

    return True


def validate_multus_network_macvlan__params(config, index):
    '''
    Checks the presence of Macvlan parameters also check Macvlan
    network name format and validations of "type"
    '''
    logger.info("checking Macvlan  params")
    all_data_dict_for_net_params = config.get("kubernetes").get("Networks")

    keysofallnetworks = []
    for all_keys in all_data_dict_for_net_params[index]:
        for keys_in_all_keys in all_data_dict_for_net_params[index][all_keys]:
            cni_config_data = keys_in_all_keys.get("CNI_Configuration")

        for element in cni_config_data:
            for all_keys in element:
                keysofallnetworks.extend(element.values()[0])
    counter = 0
    for element in keysofallnetworks:
        if 'macvlan_networks' in element:
            counter = counter + 1
    if counter > 0:
        pass
    else:
        logger.error("macvlan_networks should be present atleast once")
        return False
    for element in keysofallnetworks:
        if 'macvlan_networks' in element:
            if "isMaster" in element.get("macvlan_networks"):
                pass
            else:
                logger.error("isMaster Flag is absent in macvlan_networks")
                return False
            if validate_dict_data(element['macvlan_networks'],
                                  "parent_interface") and \
                    validate_dict_data(element['macvlan_networks'], "ip") and \
                    validate_dict_data(element['macvlan_networks'],
                                       "hostname") and \
                    validate_dict_data(element['macvlan_networks'],
                                       "vlanid") and \
                    validate_dict_data(element['macvlan_networks'],
                                       "master") and \
                    validate_dict_data(element['macvlan_networks'], "type") \
                    and validate_dict_data(element['macvlan_networks'],
                                           "network_name"):
                stringfornwname = element['macvlan_networks']['network_name']
                to_find = "_"
                count = stringfornwname.find(to_find)
                count2 = len(
                    filter(lambda x: x in string.uppercase, stringfornwname))

                if not (count < 1 and count2 < 1):
                    logger.error("Network_name value format is wrong ")
                    return False

                if element['macvlan_networks']['type'] == "host-local":
                    if not (validate_dict_data(element['macvlan_networks'],
                                               "rangeEnd") and
                            validate_dict_data(
                                    element['macvlan_networks'],
                                    "rangeStart") and
                            validate_dict_data(
                                    element['macvlan_networks'],
                                    "routes_dst") and
                            validate_dict_data(
                                    element['macvlan_networks'],
                                    "subnet") and
                            validate_dict_data(
                                    element['macvlan_networks'],
                                    "gateway")):
                        return False
            else:
                return False
    return True


def validate_multus_network_sriov__params(config, index):
    '''
    Checks the presence of Sriov parameters and validations of "type"
    '''
    logger.info("checking SRIOV  params")
    all_data_dict_for_net_params = config.get("kubernetes").get("Networks")

    keysofallnetworks = []
    numberofnetworkinonehost = 0
    for all_keys in all_data_dict_for_net_params[index]:
        for keys_in_all_keys in all_data_dict_for_net_params[index][all_keys]:
            cni_config_data = keys_in_all_keys.get("CNI_Configuration")

        for element in cni_config_data:
            for all_keys in element:
                keysofallnetworks.extend(element.values()[0])
    counter = 0
    for element in keysofallnetworks:
        if type(element) == dict and 'host' in element:
            counter = counter + 1
    if counter > 0:
        pass
    else:
        logger.error("Atleast one host must be there")
        return False
    i = 0
    for element in keysofallnetworks:
        if 'host' in element:
            if validate_dict_data(element['host'], "networks") and \
                    validate_dict_data(element['host'], "hostname"):
                for itemnetwork in element.get("host").get("networks"):
                    if "isMaster" in element.get("host").get("networks")[i]:
                        pass
                    else:
                        logger.error(
                            "isMaster Flag is absent in host in Sriov")
                        return False

                    numberofnetworkinonehost = numberofnetworkinonehost + 1

                    stringfornwname = element['host']['networks'][i][
                        'network_name']
                    to_find = "_"
                    count = stringfornwname.find(to_find)
                    count2 = len(filter(lambda x: x in string.uppercase,
                                        stringfornwname))

                    if (count < 1 and count2 < 1):
                        pass
                    else:
                        logger.error("Network_name value format is wrong ")
                        return False

                    if not validate_dict_data(element['host']['networks'][i],
                                              "type"):
                        return False
                    else:
                        if element['host']['networks'][i]['type'] == \
                                "host-local":
                            if not validate_dict_data(
                                    element['host']['networks'][i],
                                    "rangeStart"):
                                return False
                            if not validate_dict_data(
                                    element['host']['networks'][i],
                                    "sriov_intf"):
                                return False
                            if not validate_dict_data(
                                    element['host']['networks'][i],
                                    "rangeEnd"):
                                return False
                            if not validate_dict_data(
                                    element['host']['networks'][i],
                                    "network_name"):
                                return False
                            if not validate_dict_data(
                                    element['host']['networks'][i],
                                    "dpdk_enable"):
                                return False
                            if not validate_dict_data(
                                    element['host']['networks'][i],
                                    "sriov_gateway"):
                                return False
                            if not validate_dict_data(
                                    element['host']['networks'][i],
                                    "sriov_subnet"):
                                return False
                            i = i + 1
            else:
                return False
    return True


def validate_multus_network_weave_params(config):
    '''
    Checks the presence of weave parameters
    '''
    logger.info("checking weave_params params")
    all_data_dict_for_net_params = config.get("kubernetes").get("Networks")

    keysofallnetworks = []
    for all_keys in all_data_dict_for_net_params[1]:
        for keys_in_all_keys in all_data_dict_for_net_params[1][all_keys]:
            cni_config_data = keys_in_all_keys.get("CNI_Configuration")

        for element in cni_config_data:

            for all_keys in element:
                keysofallnetworks.extend(element.values()[0])
    counter = 0
    for element in keysofallnetworks:
        if 'weave_network' in element:
            counter = counter + 1

    if counter > 0:
        pass
    else:
        logger.error("weave_network should be present atleast once")
        return False
    for element in keysofallnetworks:
        if 'weave_network' in element:
            if "isMaster" in element.get("weave_network"):
                pass
            else:
                logger.error("isMaster Flag is absent in weave_network")
                return False
            if not (validate_dict_data(element['weave_network'],
                                       "network_name") and
                        validate_dict_data(element['weave_network'],
                                           "subnet")):
                return False
    return True


def validate_ceph_vol_tag(config):
    '''
    Checks the presence of Ceph Volume tag
    '''
    logger.info("checking ceph_vol_tag")
    all_data_dict_for_net_params = config.get("kubernetes").get(
        consts.PERSISTENT_VOLUME)
    if 'Ceph_Volume' not in all_data_dict_for_net_params.keys():
        return False
    if not validate_dict_data(all_data_dict_for_net_params, "Host_Volume"):
        return False
    return True


def validate_ceph_vol_params(config):
    '''
    Checks the presence of Ceph Volume parameters
    '''
    logger.info("checking ceph_vol_params")

    all_data_dict_for_ceph_volume_param = config.get("kubernetes").get(
        consts.PERSISTENT_VOLUME).get("Ceph_Volume")
    for all_ceph_colume_param_data in all_data_dict_for_ceph_volume_param:
        if not validate_dict_data(all_ceph_colume_param_data.get("host"),
                                  consts.HOST_NAME):
            return False
        if not validate_dict_data(all_ceph_colume_param_data.get("host"),
                                  consts.IP):
            return False
        if not validate_dict_data(all_ceph_colume_param_data.get("host"),
                                  consts.NODE_TYPE):
            return False
        if not validate_dict_data(all_ceph_colume_param_data.get("host"),
                                  consts.PASSWORD):
            return False
        if not validate_dict_data(all_ceph_colume_param_data.get("host"),
                                  "user"):
            return False
    return True


def validate_nodetype_data(config):
    '''
    Checks the presence of nodetype datatype
    '''
    logger.info("checking nodetype_data")
    all_data_dict_for_ceph_volume_param = config.get("kubernetes").get(
        consts.PERSISTENT_VOLUME).get("Ceph_Volume")

    for all_ceph_colume_param_data in all_data_dict_for_ceph_volume_param:
        if validate_dict_data(all_ceph_colume_param_data.get("host"),
                              consts.NODE_TYPE):
            if all_ceph_colume_param_data.get("host")[
                'node_type'] == "ceph_controller" or \
                            all_ceph_colume_param_data.get("host")[
                                'node_type'] == "ceph_osd":
                return True
            else:
                logger.error(
                    "ceph_controller or ceph_osd both are not "
                    "present in node_type")
                return False
        else:
            logger.error("Nodetype tag not present")
            return False
    return True


def validate_ceph_claim_params(config):
    '''
    Checks the presence of Ceph Claim tag and its parameters
    '''
    logger.info("checking ceph_claim_params")
    all_data_dict_for_ceph_volume_param = config.get("kubernetes").get(
        consts.PERSISTENT_VOLUME).get("Ceph_Volume")

    for all_ceph_colume_param_data in all_data_dict_for_ceph_volume_param:
        if consts.CEPH_CLAIMS in all_ceph_colume_param_data.get("host"):
            for element in all_ceph_colume_param_data.get("host").get(
                    "Ceph_claims"):
                dict_claim_param = element['claim_parameters']
                if not validate_dict_data(dict_claim_param, "claim_name"):
                    return False
                if not validate_dict_data(dict_claim_param, "storage"):
                    return False
        else:
            logger.error("Ceph claims tag not present ")
            return False
    return True


def validate_ceph_controller_params(config):
    '''
    Checks the presence of Ceph Controller parameters for ceph claim
    '''
    logger.info("checking ceph_controller_params")
    all_data_dict_for_ceph_volume_param = config.get("kubernetes").get(
        consts.PERSISTENT_VOLUME).get("Ceph_Volume")

    for all_ceph_colume_param_data in all_data_dict_for_ceph_volume_param:
        if all_ceph_colume_param_data.get("host")['node_type'] == \
                "ceph_controller":
            if consts.CEPH_CLAIMS in \
                    all_ceph_colume_param_data.get("host") and \
                            "second_storage" not in \
                            all_ceph_colume_param_data.get("host"):
                return True
            else:
                logger.error(
                    "for ceph_controller only CephClaim should be present")
                return False
    return True


def validate_ceph_osd__params(config):
    '''
    Checks the presence of Ceph osd parameters foe secondary storage presence
    '''
    logger.info("checking ceph_osd_params")
    all_data_dict_for_ceph_volume_param = config.get("kubernetes").get(
        consts.PERSISTENT_VOLUME).get("Ceph_Volume")

    for all_ceph_colume_param_data in all_data_dict_for_ceph_volume_param:
        if all_ceph_colume_param_data.get("host")['node_type'] == "ceph_osd":
            if consts.CEPH_CLAIMS not in all_ceph_colume_param_data.get(
                    "host") and \
                            "second_storage" in all_ceph_colume_param_data.get(
                        "host"):
                return True
            else:
                logger.error(
                    "for ceph_osd only secondary storage should be present")
                return False
    return True


def validate_dhcpmandatory(config, index):
    '''
    Checks the presence of DHCP CNI Plugin with Multus, if SRIOV or Multus
    uses dhcp as network type
    '''
    logger.info("checking dhcp mandatory values")
    all_data_dict_for_net_params = config.get("kubernetes").get("Networks")

    li_for_cni_params = []
    itemdhcp = "dhcp"
    for all_keys in all_data_dict_for_net_params[index]:
        for keys_in_all_keys in all_data_dict_for_net_params[index][all_keys]:
            li_for_cni_params.append(keys_in_all_keys)
            break
    count = 0
    val = ""

    for item in li_for_cni_params:
        val = item.get('CNI')

    if val is not None:
        if itemdhcp in li_for_cni_params[0].get("CNI"):
            count = count + 1

    li_for_cni_conf_params = []
    for all_keys in all_data_dict_for_net_params[index]:
        for keys_in_all_keys in all_data_dict_for_net_params[index][all_keys]:
            datain_cni_conf = keys_in_all_keys.get("CNI_Configuration")

        for element in datain_cni_conf:
            for all_keys in element:
                li_for_cni_conf_params.extend(element.values()[0])
    i = 0
    for element in li_for_cni_conf_params:
        if 'host' in element:
            if validate_dict_data(element['host'], "networks") and \
                    validate_dict_data(element['host'], "hostname"):
                for itemnetwork in element.get("host").get("networks"):
                    if element['host']['networks'][i]['type'] == "dhcp":
                        if count <= 0:
                            logger.error(
                                "if dhcp in sriov then dhcp must be cni")
                            return False
                    i = i + 1
    list_for_cni_conf2 = []
    for all_keys in all_data_dict_for_net_params[index]:
        for keys_in_all_keys in all_data_dict_for_net_params[index][all_keys]:
            datain_cni_conf = keys_in_all_keys.get("CNI_Configuration")
        for element in datain_cni_conf:
            list_for_cni_conf2.extend(element.values()[0])

    for element in list_for_cni_conf2:
        if 'macvlan_networks' in element:
            if element['macvlan_networks']['type'] == "dhcp":
                if count <= 0:
                    logger.error("if dhcp in macvlan then dhcp must be cni")
                    return False
    return True


counterforIsmaster = 0


def validate_count_in_deployment(config):
    '''
    Checks the presence of master fag must be true for only once
    '''
    global counterforIsmaster
    logger.info("checking count masterflag in default")
    all_data_dict_for_net_params = config.get("kubernetes").get("Networks")
    list_for_cni_conf_params = []
    count = 0
    is_master_val = all_data_dict_for_net_params[0].values()[0]["isMaster"]

    if is_master_val == "true":
        count = count + 1

    return count


counterforIsmaster = 0


def validate_masterflag_for_weave(config):
    '''
    Checks the presence of master fag must be true for only once
    '''
    global counterforIsmaster
    logger.info("checking Master Flag params")
    all_data_dict_for_net_params = config.get("kubernetes").get("Networks")
    list_for_cni_conf_params = []
    count = 0
    is_master_val = all_data_dict_for_net_params[0].values()[0]["isMaster"]

    if is_master_val == "true":
        count = count + 1

    for all_keys in all_data_dict_for_net_params[1]:
        for keys_in_all_keys in all_data_dict_for_net_params[1][all_keys]:
            datain_cni_conf = keys_in_all_keys.get("CNI_Configuration")
        for element in datain_cni_conf:
            list_for_cni_conf_params.extend(element.values()[0])

    for element in list_for_cni_conf_params:

        if 'weave_network' in element:
            is_master_for_weave = element['weave_network']['isMaster']
            if is_master_for_weave == "true":
                count = count + 1
                counterforIsmaster = counterforIsmaster + 1
    if count == 0:
        return True
    if count != 1:
        logger.info("isMaster is true more than 1 time")
        return False

    return True


def validate_masterflag_for_flannel(config):
    '''
    Checks the presence of master fag must be true for only once
    '''
    global counterforIsmaster
    logger.info("checking Master Flag params")
    all_data_dict_for_net_params = config.get("kubernetes").get("Networks")
    list_for_cni_conf_params = []
    count = 0
    is_master_val = all_data_dict_for_net_params[0].values()[0]["isMaster"]

    if is_master_val == "true":
        count = count + 1

    for all_keys in all_data_dict_for_net_params[1]:
        for keys_in_all_keys in all_data_dict_for_net_params[1][all_keys]:
            datain_cni_conf = keys_in_all_keys.get("CNI_Configuration")
        for element in datain_cni_conf:
            list_for_cni_conf_params.extend(element.values()[0])

    for element in list_for_cni_conf_params:
        if 'flannel_network' in element:
            is_master_for_flannel = element['flannel_network']['isMaster']
            if is_master_for_flannel == "true":
                count = count + 1
                counterforIsmaster = counterforIsmaster + 1
    if count == 0:
        return True
    if count != 1:
        logger.info("isMaster is true more than 1 time")
        return False
    return True


def validate_masterflag_for_macvlan(config):
    '''
    Checks the presence of master fag must be true for only once
    '''
    global counterforIsmaster
    logger.info("checking Master Flag params")
    all_data_dict_for_net_params = config.get("kubernetes").get("Networks")
    list_for_cni_conf_params = []
    count = 0
    is_master_val = all_data_dict_for_net_params[0].values()[0]["isMaster"]

    if is_master_val == "true":
        count = count + 1

    for all_keys in all_data_dict_for_net_params[1]:
        for keys_in_all_keys in all_data_dict_for_net_params[1][all_keys]:
            datain_cni_conf = keys_in_all_keys.get("CNI_Configuration")
        for element in datain_cni_conf:
            list_for_cni_conf_params.extend(element.values()[0])

    for element in list_for_cni_conf_params:
        if 'macvlan_networks' in element:
            is_master_for_macvlan = element['macvlan_networks']['isMaster']
            if is_master_for_macvlan == "true":
                count = count + 1
                counterforIsmaster = counterforIsmaster + 1

    if count == 0:
        return True
    if count != 1:
        logger.info("isMaster is true more than 1 time")
        return False

    return True


def validate_masterflag_for_sriov(config):
    '''
    Checks the presence of master fag must be true for only once
    '''
    global counterforIsmaster
    logger.info("checking Master Flag params for Sriov")
    all_data_dict_for_net_params = config.get("kubernetes").get("Networks")
    list_for_cni_conf_params = []
    count = 0
    is_master_val = all_data_dict_for_net_params[0].values()[0]["isMaster"]

    if is_master_val == "true":
        count = count + 1
    for all_keys in all_data_dict_for_net_params[1]:
        for keys_in_all_keys in all_data_dict_for_net_params[1][all_keys]:
            datain_cni_conf = keys_in_all_keys.get("CNI_Configuration")
        for element in datain_cni_conf:
            list_for_cni_conf_params.extend(element.values()[0])
    i = 0
    for element in list_for_cni_conf_params:
        if 'host' in element:
            if validate_dict_data(element['host'], "networks") and \
                    validate_dict_data(element['host'], "hostname"):

                for itemnetwork in element.get("host").get("networks"):
                    is_master_for_sriov = \
                        element['host']['networks'][i]['isMaster']

                    if is_master_for_sriov == "true":
                        count = count + 1
                        counterforIsmaster = counterforIsmaster + 1
                    i = i + 1
    if count == 0:
        return True
    if count != 1:
        logger.info("isMaster is true more than 1 time")
        return False

    return True


def ismaster_count_for_deployment(config):
    '''
   Checks the presence of master fag must be true atleast once in deployment
    '''
    global counterforIsmaster
    if counterforIsmaster > 1:
        logger.error("Ismaster is present more than once")
        return False
    if counterforIsmaster == 0 and validate_count_in_deployment(config) == 0:
        logger.error("isMaster should be true atleast once in deployment")
        return False

    if counterforIsmaster == 1 and validate_count_in_deployment(config) > 0:
        logger.error("Ismaster is present more than once")
        return False
    if counterforIsmaster > 0 and validate_count_in_deployment(config) == 1:
        logger.error("Ismaster is present more than once")
        return False
    if counterforIsmaster > 0 and validate_count_in_deployment(config) > 0:
        logger.error("Ismaster is present more than once")
        return False
    return True


def validate_dict_data(dict_name, dict_item):
    if not dict_name.get(dict_item):
        logger.error(dict_item + " item not exists !! validation failed")
        return False
    return True


def validate_dict_data2(dict_name, dict_item):
    if not dict_name.get(dict_item):
        return False
    return True


def validate_cni_params_for_network_deployment(config):
    '''
    Checks the presence of atleast one plugin in Cni tag
    '''
    index = 0
    logger.info("checking multus networks params for network deployment")
    all_data_dict_for_net_params = config.get("kubernetes").get("Networks")
    list_for_cni_params = []
    item_sriov = "sriov"
    item_macvlan = "macvlan"
    val = ""
    for all_keys in all_data_dict_for_net_params[0]:
        for keys_in_all_keys in all_data_dict_for_net_params[0][all_keys]:
            list_for_cni_params.append(keys_in_all_keys)
            break

    for item in list_for_cni_params:
        val = item.get('CNI')

    if val is not None:
        if item_sriov in list_for_cni_params[0].get("CNI"):

            if not validate_multus_network_sriov__params(config, index):
                logger.error("Sriov network or  parameters are not defined")
                return False
            if not validate_masterflag_network_dep_sriov(config):
                logger.error("master flag is true in sriov")
                return False
            if not validate_dhcpmandatory(config, index):
                logger.error("dhcp mandatory in cni if dhcp in sriov")
                return False

        if item_macvlan in list_for_cni_params[0].get("CNI"):
            if not validate_masterflag_network_dep_macvlan(config):
                logger.error("master flag is true in macvlan")
                return False
            if not validate_dhcpmandatory(config, index):
                logger.error("dhcp mandatory in cni if dhcp in macvlan")
                return False
            if not validate_multus_network_macvlan__params(config, index):
                logger.error("Macvlan network or parameters are not defined")
                return False
    return True


def validate_multus_network_cniconf__params_for_network_deployment(config):
    '''
    Checks the presence of all plugins in Cni Configuration parameters
    '''
    logger.info("checking cniconf params for dynamic deployment")
    all_data_dict_for_net_params = config.get("kubernetes").get("Networks")

    list_cni_config_params = []

    for all_keys in all_data_dict_for_net_params[0]:
        for keys_in_all_keys in all_data_dict_for_net_params[0][all_keys]:
            cni_config_data = keys_in_all_keys.get("CNI_Configuration")
        for element in cni_config_data:
            list_cni_config_params.append(element.keys())
        if ['Sriov'] not in list_cni_config_params:
            logger.error("Sriov does not exist")
            return False
        if ['Macvlan'] not in list_cni_config_params:
            logger.error("Macvlan does not exist")
            return False
    return True


def validate_ismaster_for_network_dep_and_dep_file(config,
                                                   config_deployment_bkup):
    '''
    Checks the presence of master fag must be true for only once
    '''
    logger.info("checking Master Flag params for dynamic deployment")
    all_data_dict_for_net_params = config_deployment_bkup.get("kubernetes"). \
        get("Networks")
    all_data_dict_for_net_params_dynamic_dep = config.get("kubernetes"). \
        get("Networks")
    list_for_cni_conf_params = []
    list_for_cni_conf_params_dynamic_dep = []
    count = 0
    is_master_val = all_data_dict_for_net_params[0].values()[0]["isMaster"]

    if is_master_val == "true":
        count = count + 1

    for all_keys in all_data_dict_for_net_params[1]:
        for keys_in_all_keys in all_data_dict_for_net_params[1][all_keys]:
            datain_cni_conf = keys_in_all_keys.get("CNI_Configuration")

        for element in datain_cni_conf:
            list_for_cni_conf_params.extend(element.values()[0])
    i = 0
    for element in list_for_cni_conf_params:
        if 'macvlan_networks' in element:
            is_master_for_macvlan = element['macvlan_networks']['isMaster']
            if is_master_for_macvlan == "true":
                count = count + 1
        if 'weave_network' in element:
            is_master_for_weave = element['weave_network']['isMaster']
            if is_master_for_weave == "true":
                count = count + 1
        if 'flannel_network' in element:
            is_master_for_flannel = element['flannel_network']['isMaster']
            if is_master_for_flannel == "true":
                count = count + 1
        if 'host' in element:
            for itemnetwork in element.get("host").get("networks"):
                is_master_for_sriov = \
                    element['host']['networks'][i]['isMaster']
                if is_master_for_sriov == "true":
                    count = count + 1
                i = i + 1
    for all_keys in all_data_dict_for_net_params_dynamic_dep[0]:
        for keys_in_all_keys in \
                all_data_dict_for_net_params_dynamic_dep[0][all_keys]:
            datain_cni_conf_dynamicdep = keys_in_all_keys.get(
                "CNI_Configuration")
        for element in datain_cni_conf_dynamicdep:
            list_for_cni_conf_params_dynamic_dep.extend(element.values()[0])

    for element in list_for_cni_conf_params_dynamic_dep:
        if 'macvlan_networks' in element:
            if element['macvlan_networks']['isMaster'] == "true":
                count = count + 1
        else:
            pass
        if 'host' in element:
            is_master_for_sriov1 = element['host']['networks'][0]['isMaster']
            if is_master_for_sriov1 == "true":
                count = count + 1
        else:
            pass

    if count != 1:
        logger.info("isMaster is true more than 1 time")
        return False
    return True


def validate_masterflag_network_dep_sriov(config):
    '''
    Checks the presence of master fag must be true for only once
    '''
    logger.info("checking Master Flag  params for dynamic deployment")
    all_data_dict_for_net_params = config.get("kubernetes").get("Networks")
    list_for_cni_conf_params = []
    count = 0

    for all_keys in all_data_dict_for_net_params[0]:
        for keys_in_all_keys in all_data_dict_for_net_params[0][all_keys]:
            datain_cni_conf = keys_in_all_keys.get("CNI_Configuration")

        for element in datain_cni_conf:
            list_for_cni_conf_params.extend(element.values()[0])

    for element in list_for_cni_conf_params:
        if 'host' in element:
            for itemnetwork in element.get("host").get("networks"):
                is_master_for_sriov = \
                    element['host']['networks'][0]['isMaster']
                if is_master_for_sriov == "true":
                    count = count + 1

    if count != 0:
        logger.info("isMaster is true more than 1 time")
        return False
    return True


def validate_masterflag_network_dep_macvlan(config):
    '''
    Checks the presence of master fag must be true for only once for macvlan
    '''
    logger.info("checking Master Flag  params for dynamic deployment")
    all_data_dict_for_net_params = config.get("kubernetes").get("Networks")
    list_for_cni_conf_params = []
    count = 0

    for all_keys in all_data_dict_for_net_params[0]:
        for keys_in_all_keys in all_data_dict_for_net_params[0][all_keys]:
            datain_cni_conf = keys_in_all_keys.get("CNI_Configuration")

        for element in datain_cni_conf:
            list_for_cni_conf_params.extend(element.values()[0])

    for element in list_for_cni_conf_params:

        if 'macvlan_networks' in element:
            is_master_for_macvlan = element['macvlan_networks']['isMaster']
            if is_master_for_macvlan == "true":
                count = count + 1
    if count != 0:
        logger.info("isMaster is true more than 1 time")
        return False
    return True


def validate_clean_up_dynamic(config):
    noofhosts = 0
    all_data_dict_for_nodeconfigurationparams = \
        config.get("kubernetes").get("node_configuration")
    if validate_dict_data(all_data_dict_for_nodeconfigurationparams[0],
                          "host"):
        for all_data_for_host in all_data_dict_for_nodeconfigurationparams:
            noofhosts = noofhosts + 1
            hostname = all_data_for_host.get("host")["hostname"]
            return node_del_check(hostname)
    if not get_masterandminion_count(noofhosts):
        logger.error("Minion could not be deleted")
        return False
    else:
        return True


def validate_add_dynamic(config):
    noofhosts = 0
    all_data_dict_for_nodeconfigurationparams = \
        config.get("kubernetes").get("node_configuration")
    if validate_dict_data(
            all_data_dict_for_nodeconfigurationparams[0], "host"):
        for all_data_for_host in all_data_dict_for_nodeconfigurationparams:
            noofhosts = noofhosts + 1
            hostname = all_data_for_host.get("host")["hostname"]
            return node_add_check(hostname)
    return True


def node_add_check(hostname):
    command = "ansible kube-node -i /home/1906/Ensconcek8\
    /snaps_k8s/projects/My_project/inventory.cfg --list-host \
     | awk '{if(NR>1)print}' | awk '{$1=$1};1'"
    node_name = subprocess.check_output(command, shell=True)
    if hostname in node_name:
        logger.error("given node already exist in the cluster: cannot add")
        return False
    else:
        pass
    return True


def get_masterandminion_count(noofhosts):
    command = "ansible kube-node -i /home/1906/Ensconcek8\
    /snaps_k8s/projects/My_project/inventory.cfg --list-host /" \
              "  | awk '{if(NR>1)print}' | awk '{$1=$1};1' | wc -l"
    count_for_minion = subprocess.check_output(command, shell=True)
    difference = int(count_for_minion) - noofhosts
    if difference > 0:
        return True
    else:
        logger.error("Atleast one minion must be in the cluster")
        return False


def node_del_check(hostname):
    command = "ansible kube-node -i /home/1906/Ensconcek8\
    /snaps_k8s/projects/My_project/inventory.cfg --list-host\
      | awk '{if(NR>1)print}' | awk '{$1=$1};1'"
    node_name = subprocess.check_output(command, shell=True)
    if hostname in node_name:
        pass
    else:
        logger.error("given node does not exist in the cluster: cannot delete")
        return False
    return True


def validate_dynamic_deployment_file(config):
    '''
    Calls all the validations
    '''
    logger.info("validate_dynamic_deployment_file \
     function for dynamic deployment")
    if not validate_kubernetes_tag(config):
        exit(1)
    if not validate_node_config_tag(config):
        exit(1)
    if not validate_node_config_params(config):
        exit(1)
    if not validate_add_dynamic(config):
        exit(1)
    logger.info('Dynamic Deployment file is valid')


def validate_network_deployment_file(config, config_deployment_bkup):
    '''
    Calls all the validations
    '''
    logger.info("validate_network_deployment_file \
    function for network deployment")
    logger.info("validate network yaml")
    if not validate_kubernetes_tag(config):
        exit(1)
    if not validate_network__tag(config):
        exit(1)
    else:
        if not validate_multus_network_tag_network_yaml(config):
            return True

        else:
            if not validate_cni_params_for_network_deployment(config):
                exit(1)
            if not validate_ismaster_for_network_dep_and_dep_file(
                    config, config_deployment_bkup):
                exit(1)
    logger.info('Network file is valid')

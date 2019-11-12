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
import string
from snaps_k8s.common.consts import consts
from snaps_k8s.common.utils import config_utils

logger = logging.getLogger('validation_utils')

# TODO/FIXME - Consider making the validation routine based on a YAML schema


def validate_deployment_file(config):
    """
    Calls all the validations
    """
    logger.info("validate_deployment_file function")

    validate_kubernetes_tag(config)
    validate_kubernetes_params(config)
    validate_hostnames(config)
    validate_node_config_tag(config)
    validate_node_config_params(config)
    validate_count_master_minion(config)

    if consts.HA_CONFIG_KEY in config:
        validate_api_ext_loadbalancer_tag_params(config)

    validate_countmasters(config)

    if consts.ACCESS_SEC_KEY in config:
        validate_access_and_security_params(config)

    validate_docker_repo_tag(config)
    validate_docker_repo_params(config)

    validate_proxy_params(config)

    validate_network_tag(config)
    validate_default_network_params(config)

    validate_multus_network_cni(config)
    validate_multus_network_cni_conf(config)
    validate_cni_params(config)
    validate_duplicatein_cni_and_networkplugin(config)
    ismaster_count_for_deployment(config)

    if config_utils.get_ceph_vol(config):
        validate_nodetype_data(config)
        validate_ceph_vol_params(config)
        validate_ceph_controller_params(config)
        validate_ceph_osd_params(config)

    logger.info('Deployment file is valid')


def validate_kubernetes_tag(config):
    """
    Checks the presence of Kubernetes tag
    """
    logger.info("checking kubernetes tag")
    validate_dict_data(config, consts.K8S_KEY)


def validate_kubernetes_params(config):
    """
    Checks the presence of Kubernetes parameters
    """
    logger.info("checking kubernetes params")

    k8_config = config.get(consts.K8S_KEY)
    validate_dict_data(k8_config, consts.PROJECT_NAME_KEY)
    validate_dict_data(k8_config, consts.METRICS_SERVER_KEY)
    validate_dict_data(k8_config, consts.NODE_CONF_KEY)
    validate_dict_data(k8_config, consts.DOCKER_REPO_KEY)
    validate_dict_data(k8_config, consts.NETWORKS_KEY)
    validate_dict_data(k8_config, consts.PERSIST_VOL_KEY)
    validate_dict_data(k8_config, consts.CPU_ALLOC_KEY)


def validate_hostnames(config):
    """
    Ensures that each configured hostname is unique
    :param config: the k8s config
    :raises ValidationException
    """
    logger.info('Checking to ensure all hostnames are unique')
    nodes_info = config_utils.get_nodes_ip_name_type(config)
    hostnames = set()
    for hostname, ip, node_type in nodes_info:
        hostnames.add(hostname)

    if len(nodes_info) != len(hostnames):
        raise ValidationException('Hostnames must be unique - {}'.format(
            nodes_info))


def validate_api_ext_loadbalancer_tag_params(config):
    logger.info("checking api_ext_loadbalancer_tag")
    k8s_dict = config_utils.get_k8s_dict(config)
    node_configs = config_utils.get_node_configs(config)
    ha_configs = config_utils.get_ha_config(config)

    for ha_config in ha_configs:
        validate_dict_data(k8s_dict, consts.HA_CONFIG_KEY)
        validate_dict_data(ha_config, consts.HA_API_EXT_LB_KEY)
        ha_lb_conf = ha_config[consts.HA_API_EXT_LB_KEY]
        validate_dict_data(ha_lb_conf, consts.IP_KEY)
        validate_dict_data(node_configs[0], consts.HOST_KEY)

        for node_conf in node_configs:
            if (node_conf.get(consts.HOST_KEY)[consts.IP_KEY] ==
                    ha_lb_conf[consts.IP_KEY]):
                raise ValidationException(
                    'Bootstrap ip should never match with the master or node')

        validate_dict_data(ha_lb_conf, consts.USER_KEY)
        validate_dict_data(ha_lb_conf, consts.PASSWORD_KEY)
        validate_dict_data(ha_lb_conf, consts.PORT_KEY)

        ha_lb_port = ha_lb_conf.get(consts.PORT_KEY)
        if not ha_lb_port or ha_lb_port == "" or ha_lb_port == 6443:
            raise ValidationException('Port shoud not be empty or 6443')


def validate_count_master_minion(config):
    logger.info("checking count master and minion")
    master_count = 0
    minion_count = 0
    node_configs = config_utils.get_node_configs(config)
    validate_dict_data(node_configs[0], consts.HOST_KEY)

    for node_config in node_configs:
        host = node_config[consts.HOST_KEY]
        if host[consts.NODE_TYPE_KEY] == consts.NODE_TYPE_MASTER:
            master_count = master_count + 1
        if host[consts.NODE_TYPE_KEY] == "minion":
            minion_count = minion_count + 1
    if minion_count > 0:
        pass
    else:
        logger.info("checking count master and minion")
        #raise ValidationException("At least one minion is required")
    if master_count > 0:
        pass
    else:
        raise ValidationException("At least master is required")


def __validate_load_balancer_ip(api_ext_loadbalancer_dict, hostname_map):
    """
    function to validate  loadbalancer ip must not be same as
    master/minion ip
    :param api_ext_loadbalancer_dict:
    :param hostname_map:
    :return:
    """
    logger.info("Argument List:\n api_ext_loadbalancer_dict: %s\n "
                "hostname_map: %s", api_ext_loadbalancer_dict,
                hostname_map)
    for host in hostname_map:
        if hostname_map[host] == api_ext_loadbalancer_dict.get(
                consts.HA_API_EXT_LB_KEY).get(consts.IP_KEY):
            logger.info('Alert !! load balancer ip must not be '
                        'same as master/minion ip')
            return False
    return True


def __validate_load_balancer_port(api_ext_loadbalancer_dict):
    """
    function to validate  loadbalancer port must not be same as master
    api server default port 6443
    :param api_ext_loadbalancer_dict:
    :return:
    """
    logger.info("Argument List:\n api_ext_loadbalancer_dict: %s",
                api_ext_loadbalancer_dict)
    lb_port = api_ext_loadbalancer_dict.get(
        consts.HA_API_EXT_LB_KEY).get("port")
    if lb_port == 6443:
        logger.info('Alert !! load balancer port must not be same as '
                    'master api server default port 6443  ')
        return False
    elif lb_port == "":
        logger.info('Alert !! load balancer port must not be null/empty ')
        return False

    return True


def validate_countmasters(config):
    """
    Raises an ValidationException when the master node count is even or < 1
    :param config: the k8s config dict
    :raises ValidationException
    """
    logger.info("checking Count the no of masters")
    node_info = config_utils.get_nodes_ip_name_type(config)

    master_count = 0
    for hostname, ip, node_type in node_info:
        if node_type == consts.NODE_TYPE_MASTER:
            master_count += 1

    if master_count % 2 == 1 and master_count > 0:
        return
    raise ValidationException("Number of masters must be odd")


def validate_access_and_security_params(config):
    """
    Checks the presence of access_and_security parameters
    """
    logger.info("checking basic_authentication params")

    sec_params = config_utils.get_k8s_dict(config).get(consts.ACCESS_SEC_KEY)
    if consts.AUTH_KEY in sec_params:
        auth_key = sec_params[consts.AUTH_KEY]
        if (consts.BASIC_AUTH_KEY not in auth_key
                or consts.TOKEN_AUTH_KEY not in auth_key):
            raise ValidationException(
                "Atleast one out of basic_authentication or "
                "token_authentication must be present")
        else:
            return
    else:
        raise ValidationException("authentication is not present")


def validate_node_config_tag(config):
    """
    Checks the presence of node configuration tag
    """
    logger.info("checking node config tag")
    k8s_dict = config_utils.get_k8s_dict(config)
    validate_dict_data(k8s_dict, consts.NODE_CONF_KEY)


def validate_node_config_params(config):
    """
    Checks the presence of node configuration parameters
    """
    logger.info("checking node configuration params")

    node_configs = config_utils.get_node_configs(config)
    validate_dict_data(node_configs[0], consts.HOST_KEY)

    for node_conf in node_configs:
        host_conf = node_conf[consts.HOST_KEY]
        validate_dict_data(host_conf, consts.HOSTNAME_KEY)
        validate_dict_data(host_conf, consts.IP_KEY)
        validate_dict_data(host_conf, consts.NODE_TYPE_KEY)
        validate_dict_data(host_conf, consts.LABEL_KEY)
        validate_dict_data(host_conf, consts.LBL_VAL_KEY)

        if consts.REG_PORT_KEY in host_conf:
            node_type = host_conf[consts.NODE_TYPE_KEY]
            if not (node_type != consts.NODE_TYPE_MASTER
                    or node_type != consts.NODE_TYPE_MINION):
                raise ValidationException(
                    'Node type should be either master or minion')
        validate_dict_data(host_conf, consts.PASSWORD_KEY)
        validate_dict_data(host_conf, consts.USER_KEY)


def validate_docker_repo_tag(config):
    """
    Checks the presence of docker repo tag
    """
    logger.info("checking docker repo tag")

    k8s_dict = config.get(consts.K8S_KEY)
    validate_dict_data(k8s_dict, consts.DOCKER_REPO_KEY)


def validate_docker_repo_params(config):
    """
    Checks the presence of docker repo parameters
    """
    logger.info("checking docker repo  params")
    docker_repo_params = config_utils.get_docker_repo(config)
    validate_dict_data(docker_repo_params, consts.IP_KEY)
    validate_dict_data(docker_repo_params, consts.PASSWORD_KEY)
    validate_dict_data(docker_repo_params, consts.USER_KEY)
    validate_dict_data(docker_repo_params, consts.PORT_KEY)


def validate_proxy_params(config):
    """
    Checks the presence of proxy parameters
    """
    logger.info("checking proxy  params")
    proxy_params = config_utils.get_proxy_dict(config)

    validate_dict_data(proxy_params, consts.FTP_PROXY_KEY)
    validate_dict_data(proxy_params, consts.HTTP_PROXY_KEY)
    validate_dict_data(proxy_params, consts.HTTPS_PROXY_KEY)
    validate_dict_data(proxy_params, consts.NO_PROXY_KEY)


def validate_network_tag(config):
    """
    Checks the presence of network tag
    """
    logger.info("checking networks tag")

    k8s_dict = config_utils.get_k8s_dict(config)
    validate_dict_data(k8s_dict, consts.NETWORKS_KEY)


def validate_default_network_params(config):
    """
    Checks the presence of default network tag and its parameters
    """
    logger.info("checking def networks  params")
    default_net = config_utils.get_default_network(config)
    if not default_net:
        raise ValidationException('Default network must be defined')

    validate_dict_data(default_net, consts.NET_PLUGIN_KEY)
    validate_dict_data(default_net, consts.MASTER_PLUGIN_KEY)
    validate_dict_data(default_net, consts.SRVC_SUB_KEY)
    validate_dict_data(default_net, consts.POD_SUB_KEY)
    validate_dict_data(default_net, consts.NETWORK_NAME_KEY)


def validate_multus_network_cni(config):
    """
    Checks the presence of CNI tag in Multus network and also checks
    presence of multus network tag
    """
    logger.info("checking multus networks CNI ")
    mult_nets = config_utils.get_multus_network(config)
    for mult_net in mult_nets:
        if consts.MULTUS_CNI_KEY in mult_net:
            return
    raise ValidationException(
        '{} config does not exist'.format(consts.MULTUS_CNI_KEY))


def validate_multus_network_cni_conf(config):
    """
    Checks the presence of CNI Configuration tag in Multus network
    and also checks presence of multus network tag
    """
    logger.info("checking multus networks CNI CONF tag")
    mult_nets = config_utils.get_multus_network(config)
    for mult_net in mult_nets:
        if consts.MULTUS_CNI_CONFIG_KEY in mult_net:
            return
    raise ValidationException('{} config does not exist'.format(
        consts.MULTUS_CNI_CONFIG_KEY))


def validate_cni_params(config):
    """
    Checks the presence of atleast one plugin in Cni tag
    """
    logger.info("checking multus networks  params")
    net_configs = config_utils.get_networks(config)
    cni_params = []

    for all_keys in net_configs[1]:
        for keys_in_all_keys in net_configs[1][all_keys]:
            cni_params.append(keys_in_all_keys)
            break

    for cni_param in cni_params:
        if cni_param.get(consts.MULTUS_CNI_KEY):
            if consts.WEAVE_TYPE in cni_param.get(consts.MULTUS_CNI_KEY):
                validate_multus_network_weave_params(config)

            if consts.FLANNEL_TYPE in cni_param.get(consts.MULTUS_CNI_KEY):
                validate_multus_network_flannel_params(config)

            if consts.SRIOV_TYPE in cni_param.get(consts.MULTUS_CNI_KEY):
                validate_multus_network_sriov_params(config)

            if consts.MACVLAN_TYPE in cni_param.get(consts.MULTUS_CNI_KEY):
                validate_multus_network_macvlan_params(config)

    validate_dhcpmandatory(config)


def validate_duplicatein_cni_and_networkplugin(config):
    """
    Checks if there exists the same plugin in both default network
    plugin tag and in Cni parameters
    """
    logger.info("checking duplicate values")
    net_configs = config_utils.get_networks(config)
    networkpluginvalue = net_configs[0].values()[0][
        consts.NET_PLUGIN_KEY]

    net_elems = config_utils.get_multus_net_elems(config)
    if (consts.WEAVE_TYPE in net_elems
            and consts.WEAVE_TYPE == networkpluginvalue):
        raise ValidationException("duplicate weave")
    if (consts.FLANNEL_TYPE in net_elems
            and consts.FLANNEL_TYPE == networkpluginvalue):
        raise ValidationException("duplicate flannel")
    if (consts.SRIOV_TYPE in net_elems
            and consts.SRIOV_TYPE == networkpluginvalue):
        raise ValidationException("duplicate Sriov")
    if (consts.MACVLAN_TYPE in net_elems
            and consts.MACVLAN_TYPE == networkpluginvalue):
        raise ValidationException("duplicate macvlan")


def validate_multus_network_flannel_params(config):
    """
    Checks the presence of Flannel network parameters
    """
    logger.info("checking flannelnet params")
    flannel_nets = config_utils.get_multus_cni_flannel_cfgs(config)
    if len(flannel_nets) == 0:
        raise ValidationException('Requires at least one flannel network')

    for flannel_net in flannel_nets:
        validate_dict_data(flannel_net, consts.FLANNEL_NET_DTLS_KEY)
        flannel_dtls = flannel_net[consts.FLANNEL_NET_DTLS_KEY]
        validate_dict_data(flannel_dtls, consts.MASTER_PLUGIN_KEY)
        validate_dict_data(flannel_dtls, consts.NETWORK_NAME_KEY)
        validate_dict_data(flannel_dtls, consts.NETWORK_KEY)
        validate_dict_data(flannel_dtls, consts.SUBNET_KEY)


def validate_multus_network_macvlan_params(config):
    """
    Checks the presence of Macvlan parameters also check Macvlan
    network name format and validations of "type"
    """
    logger.info("checking Macvlan params")
    macvlan_nets = config_utils.get_multus_cni_macvlan_cfgs(config)
    if len(macvlan_nets) == 0:
        raise ValidationException('At least one macvlan network required')

    for macvlan_net in macvlan_nets:
        macvlan_conf = macvlan_net[consts.MACVLAN_NET_DTLS_KEY]
        validate_dict_data(macvlan_conf, consts.MACVLAN_PARENT_INTF_KEY)
        validate_dict_data(macvlan_conf, consts.HOSTNAME_KEY)
        validate_dict_data(macvlan_conf, consts.IP_KEY)
        validate_dict_data(macvlan_conf, consts.NODE_TYPE_MASTER)
        validate_dict_data(macvlan_conf, consts.TYPE_KEY)
        validate_dict_data(macvlan_conf, consts.NETWORK_NAME_KEY)

        net_name = macvlan_conf[consts.NETWORK_NAME_KEY]
        to_find = "_"
        count = net_name.find(to_find)
        count2 = len(filter(lambda x: x in string.uppercase, net_name))

        if not (count < 1 and count2 < 1):
            raise ValidationException("Network_name value format is wrong ")

        if macvlan_conf[consts.TYPE_KEY] == consts.NET_TYPE_LOCAL_TYPE:
            validate_dict_data(macvlan_conf, consts.RANGE_END_KEY)
            validate_dict_data(macvlan_conf, consts.RANGE_START_KEY)
            validate_dict_data(macvlan_conf, consts.ROUTES_DST_KEY)
            validate_dict_data(macvlan_conf, consts.SUBNET_KEY)
            validate_dict_data(macvlan_conf, consts.GATEWAY_KEY)


def validate_multus_network_sriov_params(config):
    """
    Checks the presence of Sriov parameters and validations of "type"
    """
    logger.info("checking SRIOV  params")

    sriov_hosts = config_utils.get_multus_cni_sriov_cfgs(config)

    for sriov_host in sriov_hosts:
        validate_dict_data(sriov_host, consts.HOST_KEY)
        host_data = sriov_host[consts.HOST_KEY]
        validate_dict_data(host_data, consts.SRIOV_NETWORKS_KEY)
        net_configs = host_data[consts.SRIOV_NETWORKS_KEY]

        for net_config in net_configs:
            validate_dict_data(net_config, consts.MASTER_PLUGIN_KEY)
            validate_dict_data(net_config, consts.HOSTNAME_KEY)
            validate_dict_data(net_config, consts.NETWORK_NAME_KEY)
            validate_dict_data(net_config, consts.TYPE_KEY)

            if net_config[consts.TYPE_KEY] == consts.NET_TYPE_LOCAL_TYPE:
                validate_dict_data(net_config, consts.RANGE_START_KEY)
                validate_dict_data(net_config, consts.RANGE_END_KEY)
                validate_dict_data(net_config, consts.SRIOV_INTF_KEY)
                validate_dict_data(net_config, consts.NETWORK_NAME_KEY)
                validate_dict_data(net_config, consts.SRIOV_DPDK_ENABLE_KEY)
                validate_dict_data(net_config, consts.SRIOV_GATEWAY_KEY)
                validate_dict_data(net_config, consts.SRIOV_SUBNET_KEY)


def validate_multus_network_weave_params(config):
    """
    Checks the presence of weave parameters
    """
    logger.info("checking weave_params params")
    weave_nets = config_utils.get_multus_cni_weave_cfgs(config)
    for weave_net in weave_nets:
        weave_details = weave_net[consts.WEAVE_NET_DTLS_KEY]
        validate_dict_data(weave_details, consts.MASTER_PLUGIN_KEY)
        validate_dict_data(weave_details, consts.NETWORK_NAME_KEY)
        validate_dict_data(weave_details, consts.SUBNET_KEY)


def validate_ceph_vol_params(config):
    """
    Checks the presence of Ceph Volume parameters
    """
    logger.info("checking ceph_vol_params")

    ceph_vols = config_utils.get_ceph_vol(config)

    for ceph_vol in ceph_vols:
        validate_dict_data(ceph_vol, consts.HOST_KEY)

        ceph_host = ceph_vol[consts.HOST_KEY]
        validate_dict_data(ceph_host, consts.IP_KEY)
        validate_dict_data(ceph_host, consts.NODE_TYPE_KEY)
        validate_dict_data(ceph_host, consts.PASSWORD_KEY)
        validate_dict_data(ceph_host, consts.USER_KEY)


def validate_nodetype_data(config):
    """
    Checks the presence of nodetype datatype
    """
    logger.info("checking nodetype_data")
    ceph_vol_hosts = config_utils.get_ceph_vol(config)
    for ceph_vol_host in ceph_vol_hosts:
        host_conf = ceph_vol_host[consts.HOST_KEY]
        validate_dict_data(host_conf, consts.NODE_TYPE_KEY)
        node_type = host_conf[consts.NODE_TYPE_KEY]

        if (node_type != consts.CEPH_CTRL_TYPE
                and node_type != consts.CEPH_OSD_TYPE):
            raise ValidationException(
                'Ceph node type is not {} or {}'.format(
                    consts.CEPH_CTRL_TYPE, consts.CEPH_OSD_TYPE))


def validate_ceph_controller_params(config):
    """
    Checks the presence of Ceph Controller parameters for ceph claim
    """
    logger.info("checking ceph_controller_params")
    ceph_hosts = config_utils.get_ceph_vol(config)
    for ceph_host in ceph_hosts:
        ceph_host_data = ceph_host[consts.HOST_KEY]
        if ceph_host_data[consts.NODE_TYPE_KEY] == consts.CEPH_CTRL_TYPE:
            validate_dict_data(ceph_host_data, consts.CEPH_CLAIMS_KEY)
            claims = ceph_host_data[consts.CEPH_CLAIMS_KEY]
            for claim in claims:
                claim_params = claim[consts.CLAIM_PARAMS_KEY]
                validate_dict_data(claim_params, consts.CEPH_CLAIM_NAME_KEY)
                validate_dict_data(claim_params, consts.CEPH_STORAGE_KEY)
        else:
            validate_dict_data(ceph_host_data, consts.STORAGE_TYPE_KEY)


def validate_ceph_osd_params(config):
    """
    Checks the presence of Ceph osd parameters foe secondary storage presence
    """
    logger.info("checking ceph_osd_params")
    ceph_hosts = config_utils.get_ceph_vol(config)

    for ceph_host in ceph_hosts:
        ceph_host_data = ceph_host[consts.HOST_KEY]
        if ceph_host_data[consts.NODE_TYPE_KEY] == consts.CEPH_OSD_TYPE:
            if (consts.CEPH_CLAIMS_KEY not in ceph_host_data
                    and consts.STORAGE_TYPE_KEY in ceph_host_data):
                return
            else:
                raise ValidationException(
                    "for ceph_osd only secondary storage should be present")


def validate_dhcpmandatory(config):
    """
    Checks the presence of DHCP CNI Plugin with Multus, if SRIOV or Multus
    uses dhcp as network type
    """
    logger.info("checking dhcp mandatory values")
    has_dhcp = False
    macvlan_nets = config_utils.get_multus_cni_macvlan_cfgs(config)
    for macvlan_net in macvlan_nets:
        macvlan_conf = macvlan_net[consts.MACVLAN_NET_DTLS_KEY]
        if macvlan_conf[consts.TYPE_KEY] == consts.DHCP_TYPE:
            has_dhcp = True
            break

    if not has_dhcp:
        sriov_nets = config_utils.get_multus_cni_sriov_cfgs(config)
        for sriov_net in sriov_nets:
            sriov_conf = sriov_net[consts.HOST_KEY]
            sriov_net_confs = sriov_conf[consts.SRIOV_NETWORKS_KEY]
            for sriov_net_conf in sriov_net_confs:
                if sriov_net_conf[consts.TYPE_KEY] == consts.DHCP_TYPE:
                    has_dhcp = True
                    break

    if has_dhcp:
        cni_types = config_utils.get_multus_net_elems(config)
        if consts.DHCP_TYPE not in cni_types:
            raise ValidationException(
                'DHCP must be in the {} list'.format(consts.MULTUS_CNI_KEY))


def ismaster_count_for_deployment(config):
    """
   Checks the presence of master fag must be true atleast once in deployment
    """
    master_count = 0
    dflt_net = config_utils.get_default_network(config)
    if config_utils.bool_val(dflt_net[consts.MASTER_PLUGIN_KEY]):
        master_count += 1

    multus_nets = config_utils.get_multus_cni_cfgs(config)
    for multus_net in multus_nets:
        if consts.FLANNEL_NET_TYPE in multus_net:
            networks = multus_net[consts.FLANNEL_NET_TYPE]
            for network in networks:
                validate_dict_data(network, consts.FLANNEL_NET_DTLS_KEY)
                details = network[consts.FLANNEL_NET_DTLS_KEY]
                if config_utils.bool_val(details[consts.MASTER_PLUGIN_KEY]):
                    master_count += 1
        if consts.WEAVE_NET_TYPE in multus_net:
            networks = multus_net[consts.WEAVE_NET_TYPE]
            for network in networks:
                validate_dict_data(network, consts.WEAVE_NET_DTLS_KEY)
                details = network[consts.WEAVE_NET_DTLS_KEY]
                if config_utils.bool_val(details[consts.MASTER_PLUGIN_KEY]):
                    master_count += 1
        if consts.MACVLAN_NET_TYPE in multus_net:
            networks = multus_net[consts.MACVLAN_NET_TYPE]
            for network in networks:
                validate_dict_data(network, consts.MACVLAN_NET_DTLS_KEY)
                details = network[consts.MACVLAN_NET_DTLS_KEY]
                if config_utils.bool_val(details[consts.MASTER_PLUGIN_KEY]):
                    master_count += 1
        if consts.SRIOV_NET_TYPE in multus_net:
            net_hosts = multus_net[consts.SRIOV_NET_TYPE]
            for net_host in net_hosts:
                validate_dict_data(net_host, consts.HOST_KEY)
                host_conf = net_host[consts.HOST_KEY]
                validate_dict_data(host_conf, consts.SRIOV_NETWORKS_KEY)
                networks = host_conf[consts.SRIOV_NETWORKS_KEY]
                for network in networks:
                    if config_utils.bool_val(network[
                                                 consts.MASTER_PLUGIN_KEY]):
                        master_count += 1

    if master_count > 1:
        raise ValidationException('isMaster is present more than once')


def validate_dict_data(dict_to_validate, dict_item):
    if dict_to_validate.get(dict_item) is None:
        raise ValidationException('Missing tag {}'.format(dict_item))


class ValidationException(Exception):
    """
    Exception to raise when there are issues with the configuration
    """

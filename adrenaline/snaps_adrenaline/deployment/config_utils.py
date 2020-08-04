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
import logging
# noinspection PyCompatibility
from StringIO import StringIO

import os
import uuid

from ruamel import yaml
from jinja2 import FileSystemLoader, Environment
from snaps_k8s.common.utils import config_utils

from snaps_adrenaline.playbooks import consts

logger = logging.getLogger('config_utils')


def persist_config_to_file(config, conf_dir):
    """
    Creates a YAML file from a dict
    :param config: the dictionary to store
    :param conf_dir: the directory used to store the config file
    :return: the closed file object
    """
    if not os.path.isdir(conf_dir):
        os.mkdir(conf_dir)

    relative_file_path = "{}/{}".format(conf_dir, str(uuid.uuid4()))
    file_path = os.path.expanduser(relative_file_path)

    yaml_from_dict = yaml.dump(config, Dumper=yaml.RoundTripDumper)

    logger.info('Saving [%s] to file [%s]', yaml_from_dict, file_path)
    with open(file_path, 'wb') as save_file:
        save_file.write(yaml_from_dict)

    logger.info('Closing file [%s]', save_file.name)
    save_file.close()

    return save_file


def get_node_ips_from_config(boot_config):
    """
    Returns the IPs of the configured nodes
    :param boot_config: the snaps-boot config to parse
    :return: a list if IPs for the given nodes
    """
    out_hosts = list()
    if ('PROVISION' in boot_config
            and 'DHCP' in boot_config['PROVISION']
            and 'subnet' in boot_config['PROVISION']['DHCP']):
        for subnet in boot_config['PROVISION']['DHCP']['subnet']:
            if 'bind_host' in subnet:
                for bind_host in subnet['bind_host']:
                    if 'ip' in bind_host:
                        out_hosts.append(bind_host['ip'])
    return out_hosts


def get_node_ip(boot_conf, hostname):
    """
    Returns the IPs of the configured nodes
    :param boot_conf: the snaps-boot config to parse
    :param hostname: the hostname in boot_conf that contains the IP returned
    :return: a list if IPs for the given nodes
    """
    if ('PROVISION' in boot_conf and 'STATIC' in boot_conf['PROVISION']
            and 'host' in boot_conf['PROVISION']['STATIC']):
        for host in boot_conf['PROVISION']['STATIC']['host']:
            if host['name'] == hostname:
                return host['access_ip']

    raise Exception('Unable to obtain ip of host {}'.format(hostname))


def get_master_node_ips(boot_conf, hb_conf):
    """
    Returns a list of IPs for all master nodes
    :param boot_conf: the snaps-boot configuration dict
    :param hb_conf: the adrenaline configuration dict
    :return: a list of IP addresses
    """
    return __get_node_ips(boot_conf, hb_conf, 'masters')


def get_minion_node_ips(boot_conf, hb_conf):
    """
    Returns a list of IPs for all master nodes
    :param boot_conf: the snaps-boot configuration dict
    :param hb_conf: the adrenaline configuration dict
    :return: a list of IP addresses
    """
    return __get_node_ips(boot_conf, hb_conf, 'minions')


def __get_node_ips(boot_conf, hb_conf, node_type):
    """
    Returns a list of IPs for all nodes of a given type
    :param boot_conf: the snaps-boot configuration dict
    :param hb_conf: the adrenaline configuration dict
    :param node_type: a string denoting the node type ('master'|'minion')
    :return: a list of IP addresses or an empty list
    """
    out = list()
    master_node_names = hb_conf[node_type]
    for master_node_name in master_node_names:
        out.append(get_node_ip(boot_conf, master_node_name))

    return out


def get_node_user(boot_config):
    """
    Returns the user for all nodes
    :param boot_config: the snaps-boot config to parse
    :return: the name
    :raises: Exception when not found
    """
    logger.debug('Looking up TFTP user')

    conf = __get_first_node_config(boot_config)
    if conf:
        logger.debug('Checking %s', conf)
        if conf.get('ubuntu'):
            return conf['ubuntu']['user']
        elif conf.get('centos'):
            return conf['centos']['user']
        elif 'user' in conf:
            return conf['user']

    raise Exception('Unable to find node user in conf - %s', conf)


def get_node_pass(boot_config):
    """
    Returns the user's password for all nodes
    :param boot_config: the snaps-boot config to parse
    :return: the password
    :raises: Exception when not found
    """
    logger.debug('Looking up TFTP password')

    conf = __get_first_node_config(boot_config)
    if conf:
        logger.debug('Checking %s', conf)
        if conf.get('ubuntu'):
            return conf['ubuntu']['password']
        elif conf.get('centos'):
            return conf['centos']['password']
        elif 'password' in conf:
            return conf['password']

    raise Exception('Unable to find node password in conf - %s', conf)


def __get_first_node_config(boot_config):
    """
    Retrieves the first pxe_server_configuration
    :param boot_config: the config to query and extract
    :return:
    """
    if 'PROVISION' in boot_config and 'TFTP' in boot_config['PROVISION']:
        if ('pxe_server_configuration' in boot_config['PROVISION']['TFTP']
            and isinstance(
                boot_config['PROVISION']['TFTP']['pxe_server_configuration'],
                list)):
            return boot_config['PROVISION']['TFTP'][
                'pxe_server_configuration'][0]
        else:
            return boot_config['PROVISION']['TFTP']['pxe_server_configuration']
    else:
        logger.error('Cannot find PXE server config')


def __generate_node_config(boot_conf, hb_conf):
    """
    Generates the node configuration for snaps-kubernetes
    :param boot_conf: the snaps-boot config dict
    :param hb_conf: the adrenaline config dict
    :return: list of dict containing the configuration of each kubernetes node
    """
    out_list = list()
    env = Environment(loader=FileSystemLoader(
        searchpath=os.path.dirname(consts.K8S_DEPOY_NODE_CONFIG_TMPLT)))
    template = env.get_template(
        os.path.basename(consts.K8S_DEPOY_NODE_CONFIG_TMPLT))

    boot_nodes = __get_boot_node_data(boot_conf, hb_conf)
    for boot_node in boot_nodes:
        host_dict = yaml.safe_load(template.render(**boot_node))
        out_list.append({'host': host_dict})
    return out_list


def __get_boot_node_data(boot_conf, hb_conf):
    """
    Returns a list of dict objects containing the substitution variables
    for each configured node
    :param boot_conf: the snaps-boot config
    :param hb_conf: the adrenaline config dict
    :return: a list of dict for k8s configuration
    """
    out_list = list()

    boot_hosts = boot_conf['PROVISION']['STATIC']['host']
    master_names = hb_conf['masters']
    minion_names = hb_conf['minions']
    node_passwd = get_node_pass(boot_conf)

    for boot_host in boot_hosts:
        port = None
        node_type = None
        if boot_host['name'] in master_names:
            node_type = 'master'
            port = consts.MASTER_CONFIG_PORT
        if boot_host['name'] in minion_names:
            node_type = 'minion'
            port = consts.MINION_CONFIG_PORT

        access_ip = None
        boot_type = hb_conf.get('boot_intf_type')
        if boot_type:
            for interface in boot_host['interfaces']:
                if interface['type'] == boot_type:
                    access_ip = interface['address']
        else:
            access_ip = boot_host['access_ip']

        if not access_ip:
            raise Exception('Unable to obtain an access IP')

        if node_type:
            out_list.append({
                'hostname': boot_host['name'],
                'node_ip': access_ip,
                'registry_port': port,
                'node_type': node_type,
                'label_value': boot_host['name'],
                'node_host_pass': node_passwd,
            })
            port += 1

    return out_list


def k8s_conf_dict(boot_conf, hb_conf):
    """
    Generates and returns a dict of the k8s deployment configuration
    :param boot_conf: the snaps-boot config dict
    :param hb_conf: the adrenaline config dict
    :return: dict with one key 'kubernetes' containing the rest of the data
    """
    k8s_dict = __generate_base_k8s_config(boot_conf, hb_conf)
    k8s_dict['kubernetes']['node_configuration'] = __generate_node_config(
        boot_conf, hb_conf)

    return k8s_dict


def __generate_base_k8s_config(boot_conf, hb_conf):
    """
    Generates a snaps-kubernetes configuration dict without any
    node_configuration
    :param boot_conf: the snaps-boot config dict
    :param hb_conf: the adrenaline config dict
    :return: a dict
    """
    out_conf = dict()
    out_conf.update(hb_conf)

    if 'master_ip' not in hb_conf:
        repo_node = hb_conf['docker']['repo_host']
        ip = get_node_ip(boot_conf, repo_node)
        out_conf['master_ip'] = ip

    if 'parent_intf' not in hb_conf:
        parent_intf = hb_conf['node_info']['macvlan_intf']
        out_conf['parent_intf'] = parent_intf

    if 'node_host_pass' not in hb_conf:
        repo_pass = hb_conf['docker']['repo_pass']
        out_conf['node_host_pass'] = repo_pass

    if 'minions' in hb_conf and isinstance(hb_conf['minions'], list):
        out_conf['hostname'] = hb_conf['minions'][0]

    if 'minions' in hb_conf and isinstance(hb_conf['minions'], list):
        out_conf['hostname'] = hb_conf['minions'][0]

    if not out_conf.get('k8s_version'):
        out_conf['k8s_version'] = consts.DFLT_K8S_VERSION

    if not out_conf.get('kubespray_url'):
        out_conf['kubespray_url'] = consts.DFLT_KUBESPRAY_URL

    if not out_conf.get('kubespray_branch'):
        out_conf['kubespray_branch'] = consts.DFLT_KUBESPRAY_BRANCH

    if 'api_host' in hb_conf:
        out_conf['api_host'] = hb_conf['api_host']

    env = Environment(loader=FileSystemLoader(
        searchpath=os.path.dirname(consts.K8S_DEPLOY_TMPLT)))
    template = env.get_template(os.path.basename(consts.K8S_DEPLOY_TMPLT))
    env_str = template.render(**out_conf)
    out_dict = yaml.safe_load(StringIO(env_str))

    if hb_conf.get('Persistent_Volumes'):
        out_dict['kubernetes']['Persistent_Volumes'] = hb_conf.get(
            'Persistent_Volumes')
    if hb_conf.get('Networks'):
        out_dict['kubernetes']['Networks'] = hb_conf.get('Networks')
    if hb_conf.get('secrets'):
        out_dict['kubernetes']['secrets'] = hb_conf.get('secrets')
    if hb_conf.get('proxies'):
        out_dict['kubernetes']['proxies'] = hb_conf.get('proxies')
    if hb_conf.get('kubespray_proxies'):
        out_dict['kubernetes']['kubespray_proxies'] = hb_conf.get(
            'kubespray_proxies')
    if hb_conf.get('enable_kubevirt') :
        out_dict['enable_kubevirt'] = hb_conf['enable_kubevirt']

    return out_dict


def get_k8s_version(k8s_conf, maj_min_only=False):
    """
    Returns the k8s version from the k8s configuration (numbers only)
    :param k8s_conf: the k8s configuration
    :param maj_min_only: when true, only the major.minor values will be
           returned (Default: False)
    :return: the version
    """
    version = config_utils.get_version(k8s_conf)
    tokens = version.split('.')

    if len(tokens) < 2:
        raise Exception('Version must have a major and minor version')

    if maj_min_only:
        return "{}.{}".format(tokens[0], tokens[1]).strip('v')
    else:
        return version.strip('v')

def get_kubevirt_cfg(k8s_conf):
    """
    Returns kubevirt enablement choice
    :return: true/false
    """
    if k8s_conf.get('enable_kubevirt') :
        return k8s_conf['enable_kubevirt']

def get_master_ip(k8s_conf):
    """
    Returns maser node ip
    """
    master_ip = list()
    for i in k8s_conf['kubernetes']['node_configuration'] :
        if i['host'].get('node_type') == 'master':
            master_ip.append(i['host'].get('ip'))
    return master_ip


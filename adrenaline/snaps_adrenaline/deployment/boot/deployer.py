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
import pkg_resources
import time
import fileinput

from snaps.openstack import create_instance
from snaps.openstack.os_credentials import OSCreds
from snaps.openstack.utils import nova_utils, keystone_utils, neutron_utils
from snaps.openstack.utils.nova_utils import RebootType
from snaps_boot.provision import rebar_utils, ipmi_utils, pxe_utils
from snaps_common.ansible_snaps import ansible_utils
from snaps_common.file import file_utils
from snaps_common.ssh import ssh_utils

from snaps_adrenaline.deployment import config_utils
from snaps_adrenaline.playbooks import consts

logger = logging.getLogger('snaps_boot_deployer')


def deploy(boot_conf, hb_conf, user, os_env_file=None, boot_timeout=1800):
    """
    Installs and sets up PXE bootable machines with and OS and network
    configuration
    :param boot_conf: boot configuration dict
    :param hb_conf: adrenaline configuration dict
    :param user: the sudo user used to apply the playbook
    :param os_env_file: when environment is on OpenStack, this file is required
    :param boot_timeout: number of seconds to wait for PXE booting to complete
    :raises: Exception should snaps-boot fail to execute successfully
    """

    # Install and setup Digital Rebar
    # add post_script file to boot_conf dict
    ps_file = pkg_resources.resource_filename(
        'snaps_adrenaline.deployment.boot', 'post_script')

    ovs_dpdk_enabled = hb_conf['enable_ovs_dpdk']
    if ovs_dpdk_enabled == 'true':
        logger.info('ovs-dpdk:true: ON the post-script ovs-dpdk-flag')
        for line in fileinput.input(ps_file, inplace=True):
            print line.replace('OVS_DPDK_FLAG="OFF"', 'OVS_DPDK_FLAG="ON"'),

    if ovs_dpdk_enabled == 'false':
        logger.info('ovs-dpdk:false: OFF the post-script ovs-dpdk-flag')
        for line in fileinput.input(ps_file, inplace=True):
            print line.replace('OVS_DPDK_FLAG="ON"', 'OVS_DPDK_FLAG="OFF"'),

    pxe_config = boot_conf['PROVISION']['TFTP']['pxe_server_configuration']
    pxe_config['ubuntu']['post_script_location'] = ps_file

    rebar_utils.install_config_drp(consts.REBAR_SESSION, boot_conf)

    # Reboot for pxelinux.0 download and installation
    if os_env_file:
        __reboot_openstack_nodes(os_env_file)
    else:
        if boot_conf['PROVISION'].get('HYPERVISOR'):
            __reboot_libvirt_nodes(boot_conf)
        else:
            ipmi_utils.reboot_pxe(boot_conf)

    __block_until_complete(boot_conf, boot_timeout, suspend=450)

    if not os_env_file:
        try:
            pxe_utils.static_ip_configure(boot_conf)
        except Exception as e:
            logger.warn('Unexpected exception configuring NICs trying once'
                        ' more again in 60 seconds - [%s]', e)
            time.sleep(60)
            pxe_utils.static_ip_configure(boot_conf)
    else:
        # TODO - make the default MTU setting configurable for OpenStack
        __override_default_mtu(boot_conf)

    __setup_gpu(boot_conf, hb_conf, user)
    __setup_fpga(boot_conf, hb_conf, user)
    __setup_ovs_dpdk(boot_conf, hb_conf, user) 
    __post_hw_setup_reboot(boot_conf, hb_conf, user)


def __setup_build_server(boot_conf):
    """
    This function is responsible for creating the DHCP server and starting the
    PXE boot process
    :param boot_conf: boot configuration dict
    """
    rebar_utils.install_config_drp(consts.REBAR_SESSION, boot_conf)


def __override_default_mtu(boot_conf, mtu=1400):
    """
    Reboots baremetal nodes via an Ansible call to iaas_launch.py
    :param boot_conf: the snaps-boot configuration dict
    :param mtu: the MTU value for the nodes (default 1400)
    """
    logger.info('Setting default MTU')

    hosts = config_utils.get_node_ips_from_config(boot_conf)
    ansible_utils.apply_playbook(
        consts.OVERRIDE_DFLT_MTU_PB, hosts, 'root', variables={'mtu': mtu})

    logger.info('Completed MTU reconfiguration on k8s nodes')


def __reboot_libvirt_nodes(boot_conf):
    """
    Reboots libvirt node server instances
    :param boot_conf: the snaps-boot configuration dict
    """
    host_names = []

    hosts = boot_conf['PROVISION']['STATIC']['host']
    for host in hosts:
        host_names.append(host['name'])

    hyper_host = boot_conf['PROVISION']['HYPERVISOR']['host']
    hyper_user = boot_conf['PROVISION']['HYPERVISOR']['user']

    logger.info('Attempting to reboot nodes running in libvirt on host '
                '[%s] with user [%s]', hyper_host, hyper_user)
    ansible_utils.apply_playbook(
        consts.REBOOT_LIBVIRT_VMS, [hyper_host], hyper_user,
        variables={'hosts': host_names})


def __reboot_openstack_nodes(os_manifest_file):
    """
    Reboots openstack node server instances
    :param os_manifest_file: the OpenStack manifest
    """
    logger.info('Attempting to reboot nodes running on OpenStack')
    logger.debug('Reading in OpenStack manifest YAML file [%s]',
                 os_manifest_file)

    os_dict = file_utils.read_yaml(os_manifest_file)
    logger.debug(
        'Read config file [%s] with contents [%s]', os_manifest_file, os_dict)
    logger.debug('Looking up VMs with %s', os_dict)

    for vm_info in os_dict['vms']:
        __reboot_openstack_node(vm_info)


def __reboot_openstack_node(vm_info):
    creds_dict = vm_info.get('os_creds')
    os_creds = OSCreds(**creds_dict)
    logger.debug('Retrieving keystone session %s', creds_dict)
    os_sess = keystone_utils.keystone_session(os_creds)

    try:
        logger.debug('Retrieving OpenStack clients with %s', creds_dict)
        nova = nova_utils.nova_client(os_creds, os_sess)
        neutron = neutron_utils.neutron_client(os_creds, os_sess)
        keystone = keystone_utils.keystone_client(os_creds, os_sess)
        logger.info('Retrieved OpenStack clients')

        vm_inst = nova_utils.get_server_object_by_id(
            nova, neutron, keystone, vm_info['id'])
        logger.info('Looking up VM named [%s]', vm_inst.name)
        if vm_inst:
            logger.debug(
                'Generating VM SNAPS creator with creds [%s]', creds_dict)

            snaps_vm = create_instance.generate_creator(
                os_creds, vm_inst, None, os_creds.project_name)
            if snaps_vm:
                logger.info('Rebooting VM with name %s', vm_inst.name)
                snaps_vm.reboot(RebootType.hard)
            else:
                logger.warn('Unable to obtain a SNAPS-OO VM creator [%s]',
                            vm_inst.name)
        else:
            logger.warn('Unable to locate VM with name %s', vm_inst.name)
    finally:
        logger.info('Closing keystone session')
        keystone_utils.close_session(os_sess)


def __block_until_complete(boot_conf, timeout, suspend=0):
    """
    Function that blocks until all nodes have SSH ports opened
    :param boot_conf: boot configuration dict
    :param timeout: boot configuration dict
    :param suspend: the number of seconds to wait before polling
    :return:
    """
    host_ips = config_utils.get_node_ips_from_config(boot_conf)
    host_ip_status = dict()
    for host_ip in host_ips:
        host_ip_status[host_ip] = False

    if suspend > 0:
        logger.info('Waiting %s seconds before polling IPs %s for SSH',
                    suspend, host_ips)
        time.sleep(suspend)

    user = config_utils.get_node_user(boot_conf)
    password = config_utils.get_node_pass(boot_conf)
    logger.info('Checking nodes for SSH on %s, user - [%s], pass - [%s]',
                host_ips, user, password)

    all_completed = True
    start = time.time()
    while timeout > time.time() - start:
        all_completed = True
        for host_ip in host_ips:
            if not host_ip_status[host_ip]:
                logger.debug(
                    'Attempting to obtain ssh client - IP [%s], user - [%s],'
                    ' pass - [%s]', host_ip, user, password)
                ssh_client = ssh_utils.ssh_client(
                    host_ip, user, password=password)
                if ssh_client:
                    logger.info('Obtained ssh client to IP [%s]', host_ip)
                    if __drp_boot_complete(ssh_client):
                        host_ip_status[host_ip] = True

        for host_ip, status in host_ip_status.items():
            if not status:
                all_completed = False
                continue

        if all_completed:
            break

        time.sleep(10)

    if not all_completed:
        logger.error('Timeout connecting to all nodes - %s', host_ips)
        raise Exception('Timeout waiting for nodes to finish booting')

    logger.info('Connected to all nodes')


def __drp_boot_complete(ssh_client):
    """
    Returns True when the file /var/log/drp-boot-complete
    :param ssh_client - the SSH client to issue commands
    :return: T/F
    """
    try:
        stdin1, stdout1, sterr1 = ssh_client.exec_command(
            'ls -l /var/log/drp-boot-complete')
        if stdout1.channel.recv_exit_status() == 0:
            logger.info('Boot complete')
            return True
        else:
            return False
    except:
        return False


def __setup_gpu(boot_conf, hb_conf, user):
    """
    Installing GPU packages
    :param boot_conf: the snaps-boot dict
    :param hb_conf: the adrenaline conf dict
    :param user: the node's ssh user
    """
    logger.info('Configuring gpu setup for the nodes')

    hosts = config_utils.get_minion_node_ips(boot_conf, hb_conf)
    provision_dict = boot_conf['PROVISION']
    proxy_dict = provision_dict.get('NODE_PROXY')
    ansible_utils.apply_playbook(consts.SETUP_GPU_BOOT_PB, hosts, user,
                                 variables=proxy_dict)

    logger.info('Completed gpu setup')


def __setup_fpga(boot_conf, hb_conf, user):
    """
    Installing FPGA packages
    :param boot_conf: the snaps-boot dict
    :param hb_conf: the adrenaline conf dict
    :param user: the node's ssh user
    """
    logger.info('Configuring fpga setup for the nodes')

    hosts = config_utils.get_minion_node_ips(boot_conf, hb_conf)
    ansible_utils.apply_playbook(consts.SETUP_FPGA_BOOT_PB, hosts, user)

    logger.info('Completed fpga setup')


def __post_hw_setup_reboot(boot_conf, hb_conf, user):
    """
    Rebooting nodes with FPGAs or GPUs
    :param boot_conf: the snaps-boot dict
    :param hb_conf: the adrenaline conf dict
    :param user: the node's ssh user
    """
    logger.debug('Rebooting nodes with and FPGA or GPU')

    hosts = config_utils.get_minion_node_ips(boot_conf, hb_conf)

    reboot_hosts = set()
    for host in hosts:
        try:
            ansible_utils.apply_playbook(consts.HAS_GPU_BOOT_PB, [host], user)
            logger.info('GPU located on host [%s]', host)
            reboot_hosts.add(host)
        except:
            logger.info('GPU not found on host [%s]', host)
            pass

        try:
            ansible_utils.apply_playbook(consts.HAS_FPGA_BOOT_PB, [host], user)
            logger.info('FPGA located on host [%s]', host)
            reboot_hosts.add(host)
        except:
            logger.info('FPGA not found on host [%s]', host)
            pass

    if len(reboot_hosts) > 0:
        logger.info('Rebooting nodes - %s', reboot_hosts)
        ansible_utils.apply_playbook(consts.REBOOT_NODE, reboot_hosts, user)

def __setup_ovs_dpdk(boot_conf, hb_conf, user):
    """
    Installing ovs dpdk packages
    :param hb_conf: the adrenaline conf dict
    """
    logger.debug('__setup_ovs_dpdk')
    ovs_dpdk_enabled = hb_conf['enable_ovs_dpdk']
    if ovs_dpdk_enabled == 'true':
        logger.info('setting up ovs-dpdk')
        hosts = config_utils.get_minion_node_ips(boot_conf, hb_conf)
        ansible_utils.apply_playbook(consts.SETUP_OVS_DPDK_PB, hosts, user)
        logger.info('Completed ovs-dpdk')
    else:
        logger.info('ovs-dpdk:disabled:No reason to install ovs-dpdk')

def undeploy(boot_conf):
    """
    Cleans up the PXE imaged machines
    :param boot_conf: boot configuration dict
    :raises: Exception should snaps-kubernetes fail to undeploy successfully
    """
    rebar_utils.cleanup_drp(consts.REBAR_SESSION, boot_conf)
    # TODO/FIXME - add pb to delete contents of /tmp and ~/.ssh/known_hosts

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
import pkg_resources
from snaps import file_utils
from mock import patch
import unittest

from snaps_adrenaline.deployment.boot import deployer

TMP_KEY_FILE = '/tmp/foo'

with open(TMP_KEY_FILE, 'wb') as key_file:
    key_file.write('foo')
    key_file.close()


class DeployTests(unittest.TestCase):

    @patch('snaps_common.ansible_snaps.ansible_utils.apply_playbook')
    @patch('os.system', return_value=0)
    @patch('os.path.isfile', return_value=False)
    @patch('os.chmod', return_value=None)
    @patch('shutil.copyfile', return_value=None)
    @patch('snaps.provisioning.ansible_utils.ssh_client', return_value='foo')
    @patch('drp_python.subnet.Subnet.__init__', return_value=None)
    @patch('drp_python.subnet.Subnet.create')
    @patch('drp_python.machine.Machine.create')
    @patch('drp_python.translation_layer.reservations_translation.'
           'ReservationTranslation.open')
    @patch('drp_python.network_layer.http_session.HttpSession.authorize')
    @patch('drp_python.network_layer.http_session.HttpSession.get')
    @patch('drp_python.reservation.Reservation.create')
    @patch('snaps_boot.provision.rebar_utils.__add_machine_params')
    @patch('snaps_boot.provision.ipmi_utils.reboot_pxe')
    @patch('time.sleep')
    @patch('snaps_common.ssh.ssh_utils.ssh_client')
    @patch('snaps_adrenaline.deployment.boot.deployer.__block_until_complete')
    def test_deploy(self, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12,
                    m13, m14, m15, m16, m17, m18):
        boot_conf_filename = pkg_resources.resource_filename(
            'tests.deployment.boot.conf', 'boot.yaml')

        with open(boot_conf_filename, 'r') as boot_conf_file:
            boot_conf_file.close()

        k8s_conf_file = pkg_resources.resource_filename(
            'tests.deployment.kubernetes.conf', 'k8s.yaml')
        k8s_conf = file_utils.read_yaml(k8s_conf_file)

        user = k8s_conf['node_info']['user']
        boot_timeout = k8s_conf['build_info']['reboot_timeout']

        boot_conf = file_utils.read_yaml(boot_conf_filename)
        deployer.deploy(boot_conf, user, None, boot_timeout)

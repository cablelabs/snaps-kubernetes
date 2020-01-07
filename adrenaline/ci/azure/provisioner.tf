# Copyright (c) 2019 Cable Television Laboratories, Inc.
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

# Call ensure SSH key has correct permissions
resource "null_resource" "adrenaline-pk-setup" {
  depends_on = [azurerm_virtual_machine.snaps-hb-host]
  provisioner "local-exec" {
    command = "chmod 600 ${var.private_key_file}"
  }
}

# Call ansible scripts to run adrenaline
resource "null_resource" "adrenaline-wait-for-build-ssh" {
  depends_on = [null_resource.adrenaline-pk-setup]

  # Setup KVM on the VM to create VMs on it for testing adrenaline
  provisioner "local-exec" {
    command = <<EOT
${var.ANSIBLE_CMD} -u ${var.sudo_user} \
-i ${azurerm_public_ip.snaps-hb-pub-ip.ip_address}, \
${var.WAIT_FOR_BUILD} \
--key-file="${var.private_key_file}" \
--extra-vars " \
host=${var.build_ip_prfx}.${var.build_ip_suffix}
timeout=${var.wait_timeout}
pause_time=30
"\
EOT
  }
}

resource "random_integer" "adrenaline-ip-prfx" {
  min = 101
  max = 254
}

# Add vm host's key to build server
resource "null_resource" "adrenaline-vmhost-build-key-mgmt" {
  depends_on = [null_resource.adrenaline-wait-for-build-ssh]
  provisioner "remote-exec" {
    inline = [
      "ssh -o StrictHostKeyChecking=no ${var.sudo_user}@${var.build_ip_prfx}.${var.build_ip_suffix} 'rm -f ~/.ssh/known_hosts'",
      "ssh -o StrictHostKeyChecking=no ${var.sudo_user}@${var.build_ip_prfx}.${var.build_ip_suffix} 'touch ~/.ssh/authorized_keys'",
      "ssh -o StrictHostKeyChecking=no ${var.sudo_user}@${var.build_ip_prfx}.${var.build_ip_suffix} 'echo \"${file(var.public_key_file)}\" >> ~/.ssh/authorized_keys'",
      "ssh -o StrictHostKeyChecking=no ${var.sudo_user}@${var.build_ip_prfx}.${var.build_ip_suffix} 'chmod 600 ~/.ssh/authorized_keys'",
      "ssh -o StrictHostKeyChecking=no ${var.sudo_user}@${var.build_ip_prfx}.${var.build_ip_suffix} 'cp ~/.ssh/authorized_keys ~/.ssh/authorized_keys.bak'",
      "ssh -o StrictHostKeyChecking=no ${var.sudo_user}@${var.build_ip_prfx}.${var.build_ip_suffix} 'sudo ip addr add ${var.build_ip_prfx}.${random_integer.adrenaline-ip-prfx.result}/24 dev ens3'",
    ]
  }
  connection {
    host = azurerm_public_ip.snaps-hb-pub-ip.ip_address
    type = "ssh"
    user = var.sudo_user
    private_key = file(var.private_key_file)
  }
}

# Wait for build machine to be ready
resource "null_resource" "adrenaline-wait-for-build-apt" {
  depends_on = [null_resource.adrenaline-vmhost-build-key-mgmt]

  # Setup KVM on the VM to create VMs on it for testing adrenaline
  provisioner "local-exec" {
    command = <<EOT
${var.ANSIBLE_CMD} -u ${var.sudo_user} \
-i ${var.build_ip_prfx}.${random_integer.adrenaline-ip-prfx.result}, \
${var.WAIT_FOR_APT} \
--key-file="${var.private_key_file}" \
--ssh-common-args="-o ProxyCommand='ssh ${var.sudo_user}@${azurerm_public_ip.snaps-hb-pub-ip.ip_address} nc ${var.build_ip_prfx}.${random_integer.adrenaline-ip-prfx.result} 22'" \
EOT
  }
}

# Install and execute adrenaline
resource "null_resource" "adrenaline-execute-hb" {
  depends_on = [null_resource.adrenaline-wait-for-build-apt]

  # Setup KVM on the VM to create VMs on it for testing adrenaline
  provisioner "local-exec" {
    command = <<EOT
${var.ANSIBLE_CMD} -u ${var.sudo_user} \
-i ${var.build_ip_prfx}.${random_integer.adrenaline-ip-prfx.result}, \
${var.IMAGE_NODES} \
--key-file="${var.private_key_file}" \
--ssh-common-args="-o ProxyCommand='ssh ${var.sudo_user}@${azurerm_public_ip.snaps-hb-pub-ip.ip_address} nc ${var.build_ip_prfx}.${random_integer.adrenaline-ip-prfx.result} 22'" \
--extra-vars " \
nameserver=${var.build_ip_prfx}.1
libvirt_host=${var.build_ip_prfx}.1
libvirt_host_user=${var.sudo_user}
deploy_boot=yes
deploy_k8s=yes
src_copy_dir=${var.src_copy_dir}
build_priv_ip=${var.priv_ip_prfx}.${var.build_ip_suffix}
build_ip=${var.priv_ip_prfx}.${var.build_ip_suffix}
priv_ip_bits=${var.priv_ip_bits}
priv_ip_1=${var.priv_ip_prfx}.${var.node_1_suffix}
priv_mac_1=${var.node_1_mac_1}
priv_ip_2=${var.priv_ip_prfx}.${var.node_2_suffix}
priv_mac_2=${var.node_2_mac_1}
priv_ip_3=${var.priv_ip_prfx}.${var.node_3_suffix}
priv_mac_3=${var.node_3_mac_1}
priv_gateway=${var.priv_ip_prfx}.1
pub_gateway=${var.pub_ip_prfx}.1
priv_addr=${var.priv_ip_prfx}.0
priv_iface=ens3
admin_ip_bits=${var.admin_ip_bits}
admin_ip_1=${var.admin_ip_prfx}.${var.node_1_suffix}
admin_ip_2=${var.admin_ip_prfx}.${var.node_2_suffix}
admin_ip_3=${var.admin_ip_prfx}.${var.node_3_suffix}
admin_iface=ens8
pub_ip_bits=${var.pub_ip_bits}
pub_ip_1=${var.pub_ip_prfx}.${var.node_1_suffix}
pub_ip_2=${var.pub_ip_prfx}.${var.node_2_suffix}
pub_ip_3=${var.pub_ip_prfx}.${var.node_3_suffix}
pub_iface=ens9
node_1_name=${var.node_1_name}
node_2_name=${var.node_2_name}
node_3_name=${var.node_3_name}
broadcast_addr=${var.priv_ip_prfx}.255
domain_name=cablelabs.com
dns_addr=8.8.8.8
listen_iface=ens3
max_lease=7200
build_proxy_port=3142
pxe_pass=${var.pxe_pass}
boot_conf_path=/tmp/hosts.yaml
k8s_conf_path=/tmp/adrenaline.yaml
netmask=${var.netmask}
ip_range='${var.priv_ip_prfx}.101 ${var.priv_ip_prfx}.254'
router_ip=${var.priv_ip_prfx}.1
snaps_k8s_branch=${var.snaps_k8s_branch}
kubespray_url=${var.kubespray_url}
kubespray_branch=${var.kubespray_branch}
k8s_version=${var.k8s_version}
networking_plugin=${var.k8s_dflt_networking_plugin}
project_name=snaps-hb-ci-${var.build_id}
proxy_host=${var.build_ip_prfx}.1
proxy_port=${var.proxy_port}
"\
EOT
  }
}

# Reinject this host key into build server as kubespray seems to have whacked it
resource "null_resource" "adrenaline-vmhost-build-key-mgmt-post-install" {
  depends_on = [null_resource.adrenaline-execute-hb]
  provisioner "remote-exec" {
    inline = [
      "ssh -o StrictHostKeyChecking=no ${var.sudo_user}@${var.build_ip_prfx}.${var.build_ip_suffix} 'rm -f ~/.ssh/known_hosts'",
      "ssh -o StrictHostKeyChecking=no ${var.sudo_user}@${var.build_ip_prfx}.${var.build_ip_suffix} 'touch ~/.ssh/authorized_keys'",
      "ssh -o StrictHostKeyChecking=no ${var.sudo_user}@${var.build_ip_prfx}.${var.build_ip_suffix} 'echo \"${file(var.public_key_file)}\" >> /home/${var.sudo_user}/.ssh/authorized_keys'",
      "ssh -o StrictHostKeyChecking=no ${var.sudo_user}@${var.build_ip_prfx}.${var.build_ip_suffix} 'chmod 600 ~/.ssh/authorized_keys'",
      "ssh -o StrictHostKeyChecking=no ${var.sudo_user}@${var.build_ip_prfx}.${var.build_ip_suffix} 'cp ~/.ssh/authorized_keys ~/.ssh/authorized_keys.bak'",
    ]
  }
  connection {
    host = azurerm_public_ip.snaps-hb-pub-ip.ip_address
    type = "ssh"
    user = var.sudo_user
    private_key = file(var.private_key_file)
  }
}

# Validate adrenaline
resource "null_resource" "adrenaline-validate" {
  depends_on = [null_resource.adrenaline-vmhost-build-key-mgmt-post-install]

  # Setup KVM on the VM to create VMs on it for testing adrenaline
  provisioner "local-exec" {
    command = <<EOT
${var.ANSIBLE_CMD} -u ${var.sudo_user} \
-i ${var.build_ip_prfx}.${random_integer.adrenaline-ip-prfx.result}, \
${var.VALIDATION} \
--key-file="${var.private_key_file}" \
--ssh-common-args="-o ProxyCommand='ssh ${var.sudo_user}@${azurerm_public_ip.snaps-hb-pub-ip.ip_address} nc ${var.build_ip_prfx}.${random_integer.adrenaline-ip-prfx.result} 22'" \
--extra-vars " \
project_name=${var.build_id}
k8s_version=${var.k8s_version}
num_masters=1
num_minions=2
http_proxy=http://${var.build_ip_prfx}.1:${var.proxy_port}
https_proxy=htts://${var.build_ip_prfx}.1:${var.proxy_port}
"\
EOT
  }
}

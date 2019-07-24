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
resource "null_resource" "snaps-k8s-setup" {
  provisioner "local-exec" {
    command = "chmod 600 ${var.private_key_file}"
  }
}

# Call ansible script to setup K8s nodes
resource "null_resource" "snaps-k8s-node-setup" {
  depends_on = [null_resource.snaps-k8s-setup]

  # Install KVM dependencies
  provisioner "local-exec" {
    command = <<EOT
${var.ANSIBLE_CMD} -u ${var.sudo_user} \
-i ${aws_instance.k8s-build.public_ip},${aws_instance.k8s-node.0.public_ip},${aws_instance.k8s-node.1.public_ip}, \
${var.SETUP_K8S_NODE} \
--key-file ${var.private_key_file} \
--extra-vars "\
snaps_ci_priv_key=${var.private_key_file} \
snaps_ci_pub_key=${var.public_key_file}
"\
EOT
  }
}

# Call ansible script to deploy K8s
resource "null_resource" "snaps-k8s-deploy" {
  depends_on = [null_resource.snaps-k8s-node-setup]
  # Create KVM networks
  provisioner "local-exec" {
    command = <<EOT
${var.ANSIBLE_CMD} -u ${var.sudo_user} \
-i ${aws_instance.k8s-build.public_ip}, \
${var.DEPLOY_K8S} \
--key-file ${var.private_key_file} \
--extra-vars "\
build_id=${var.build_id} \
branch_name=${var.branch_name} \
src_copy_dir=${var.src_copy_dir} \
deployment_yaml_path=${var.deployment_yaml_path} \
sudo_user=${var.sudo_user} \
admin_iface=${var.admin_iface} \
master_admin_ip=${aws_instance.k8s-node.0.private_ip} \
minion_admin_ip=${aws_instance.k8s-node.1.private_ip} \
k8s_version=${var.k8s_version} \
node_host_pass=${var.node_host_pass} \
networking_plugin=${var.networking_plugin} \
deployment_yaml_tmplt=${var.deployment_yaml_tmplt}
"\
EOT
  }
}

# Call ansible script to validate K8s installation
resource "null_resource" "snaps-k8s-validation" {
  depends_on = [null_resource.snaps-k8s-deploy]
  # Create KVM networks
  provisioner "local-exec" {
    command = <<EOT
${var.ANSIBLE_CMD} -u ${var.sudo_user} \
-i ${aws_instance.k8s-build.public_ip}, \
${var.VALIDATE_K8S} \
--key-file ${var.private_key_file} \
--extra-vars "\
src_copy_dir=${var.src_copy_dir} \
deployment_yaml_path=${var.deployment_yaml_path}
"\
EOT
  }
}

# Call ansible script to run CNCF confomance tests
resource "null_resource" "snaps-k8s-conformance" {
  depends_on = [null_resource.snaps-k8s-validation]
  # Create KVM networks
  provisioner "local-exec" {
    command = <<EOT
${var.ANSIBLE_CMD} -u ${var.sudo_user} \
-i ${aws_instance.k8s-build.public_ip}, \
${var.CONFORMANCE} \
--key-file ${var.private_key_file} \
--extra-vars "\
project_name=${var.build_id} \
"\
EOT
  }
}

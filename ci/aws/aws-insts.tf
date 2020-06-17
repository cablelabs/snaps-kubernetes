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

# AWS EC2 Instances
resource "aws_instance" "k8s-build" {
  ami = var.ami
  instance_type = var.instance_type_build
  key_name = aws_key_pair.snaps-k8s-pk.key_name
  availability_zone = var.availability_zone

  tags = {
    Name = "snaps-k8s-ci-build-${var.build_id}"
  }

  security_groups = [aws_security_group.snaps-k8s.name]
  associate_public_ip_address = true

  # Used to ensure host is really up before attempting to apply ansible playbooks
  provisioner "remote-exec" {
    inline = [
      "sudo apt update",
      "sudo apt install python2.7 -y",
      "sudo ln /usr/bin/python2.7 /usr/bin/python"
    ]
  }

  # Remote connection info for remote-exec
  connection {
    host = self.public_ip
    type     = "ssh"
    user     = var.sudo_user
    private_key = file(var.private_key_file)
  }
}

resource "random_integer" "snaps-k8s-primary-subnet-mid" {
  min = 101
  max = 254
}

resource "aws_instance" "k8s-node" {
  count = 3
  ami = var.ami
  instance_type = var.instance_type_node
  key_name = aws_key_pair.snaps-k8s-pk.key_name
  availability_zone = var.availability_zone

  tags = {
    Name = "snaps-k8s-node-${var.build_id}"
  }

  security_groups = [aws_security_group.snaps-k8s.name]
  associate_public_ip_address = true

  # Used to ensure host is really up before attempting to apply ansible playbooks
  provisioner "remote-exec" {
    inline = [
      "sudo apt update",
      "sudo apt install python2.7 -y",
      "sudo ln /usr/bin/python2.7 /usr/bin/python"
    ]
  }

  # Remote connection info for remote-exec
  connection {
    host = self.public_ip
    type     = "ssh"
    user     = var.sudo_user
    private_key = file(var.private_key_file)
  }

  root_block_device {
    volume_size = var.boot_volume_size
  }
}

resource "random_integer" "snaps-k8s-secondary-subnet-mid" {
  min = 101
  max = 254
}

resource "aws_subnet" "snaps-k8s-secondary-subnet" {
  vpc_id = var.vpc_id
  cidr_block = "172.31.${random_integer.snaps-k8s-secondary-subnet-mid.result}.0/24"
  availability_zone = var.availability_zone
  tags = {
    Name = "snaps-k8s-secondary-subnet-${var.build_id}"
  }
}

resource "aws_network_interface" "snaps-k8s-node-secondary-intf" {
  count = 3
  subnet_id = aws_subnet.snaps-k8s-secondary-subnet.id
  security_groups = [aws_security_group.snaps-k8s.id]
  attachment {
    instance = [
      aws_instance.k8s-node.0.id,
      aws_instance.k8s-node.1.id,
      aws_instance.k8s-node.2.id,
      aws_instance.k8s-build.id
    ][count.index]
    device_index = 1
  }
}

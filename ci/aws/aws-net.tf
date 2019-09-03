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
# AWS EC2 Network Setup
resource "aws_vpc" "snaps-k8s-vpc" {
  cidr_block = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support = true
  tags = {
    Name = "snaps-k8s-vpc-${var.build_id}"
  }
}

resource "aws_internet_gateway" "snaps-k8s-gw" {
  vpc_id = aws_vpc.snaps-k8s-vpc.id
}

resource "aws_subnet" "snaps-k8s-primary-subnet" {
  vpc_id            = aws_vpc.snaps-k8s-vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = var.availability_zone
  map_public_ip_on_launch = true
  tags = {
    Name = "snaps-k8s-primary-subnet-${var.build_id}"
  }
}

resource "aws_subnet" "snaps-k8s-secondary-subnet" {
  vpc_id = aws_vpc.snaps-k8s-vpc.id
  cidr_block = "10.0.2.0/24"
  availability_zone = var.availability_zone
  tags = {
    Name = "snaps-k8s-secondary-subnet-${var.build_id}"
  }
}

resource "aws_route_table" "snaps-k8s-route" {
  vpc_id = aws_vpc.snaps-k8s-vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.snaps-k8s-gw.id
  }
}

resource "aws_route_table_association" "snaps-k8s-primary-subnet-assn" {
  subnet_id      = aws_subnet.snaps-k8s-primary-subnet.id
  route_table_id = aws_route_table.snaps-k8s-route.id
}

resource "aws_route_table_association" "snaps-k8s-secondary-subnet-assn" {
  subnet_id      = aws_subnet.snaps-k8s-secondary-subnet.id
  route_table_id = aws_route_table.snaps-k8s-route.id
}


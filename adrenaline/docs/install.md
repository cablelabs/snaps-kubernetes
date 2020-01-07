# Installation

## Introduction

Adrenaline joins together the [snaps-boot](https://github.com/cablelabs/snaps-boot)
and [snaps-kubernetes](https://github.com/cablelabs/snaps-kubernetes) projects together
to provide a one-touch provisioning solution to spinning up a Kubernetes cluster.

In addition to simply installing an operating system and Kubernetes, Adrenaline
also installs the software required by Docker and Kubernetes that allows for containers
to leverage any FPGA and GPU hardware components installed within the worker nodes
of your cluster. 

## Hardware Requirements

**Kubernetes Master Nodes**

| Hardware Required | Configuration |
| ----------------- | ------------- |
| Server machine with 64bit Intel AMD architecture. | 16GB RAM, 80+ GB Hard disk with 1 network interface. Server must be network boot Enabled and IPMI capable. |

**Kubernetes Worker (fka. Minion) Nodes**

| Hardware Required | Configuration |
| ----------------- |  ------------- |
| Server machine with 64bit Intel AMD architecture. | 16GB RAM, 80+ GB Hard disk with 1 network interface and optionally with an NVIDIA P1000 or P4000 GPU and/or Xilinx FPGA card. Server must be network boot Enabled and IPMI capable. |

**Configuration Node**

| Hardware Required | Configuration |
| ----------------- | ------------- |
| Server machine with 64bit Intel AMD architecture. | 4GB RAM, 50+ GB Hard disk with 1 network interface. |

## Configuration Node Setup for Adrenaline

1. Install the following packages
    * python 2.7.x
    * pip
    * git

1. Download cablelabs/openhw-hyperbuild from GitHub
    ```
    git clone https://github.com/cablelabs/openhw-hyperbuild.git
    ```
1. Install into Python runtime
    ```
    pip install -r openhw-hyperbuild/adrenaline/requirements-git.txt
    pip install openhw-hyperbuild/adrenaline
    ```

## Adrenaline Installation

### Configure

#### Boot
Please see configuration section from
[snaps-boot install docs](https://github.com/cablelabs/snaps-boot/blob/master/doc/source/install/install.md#3-configuration)
as this configuration is identical.

#### K8s Template
The K8s Template contains information that will be merged together with the boot
configuration to tell [snaps-kubernetes](https://github.com/cablelabs/snaps-kubernetes)
how you would like your cluster to be installed. Please see the configuration items below.
An example can also be located
[here](https://github.com/cablelabs/openhw-hyperbuild/blob/master/adrenaline/ci/playbooks/templates/adrenaline.yaml.j2)

+ k8s_version - For GPU and FPGA support, versions 1.12.0 - 1.12.5 are currently supported (default: 1.12.5)
+ kubespray_url - The git URL of the version of Kubespray you would like to use (default: https://github.com/cablelabs/kubespray)
+ kubespray_branch - The kubespray branch name (default: master)
+ project_name - As you should be able to support multiple environments from a single Configuration server,
 this value will need to be unique to your environment and the value mus only contain alphanumeric characters (required)
+ api_host - generally the IP of the last configured NIC on the first master host (required when cluster has more than
 one configured network)
+ masters - list of the hostnames of all Kubernetes master nodes as defined in the boot configuration
+ minions - list of the hostnames of all Kubernetes worker nodes as defined in the boot configuration
+ node_info
    + user - the username for all nodes used for setup
    + priv_key - the private key to the user for obtaining SSH sessions into the nodes
    + macvlan_intf - the NIC name of the interface to be used for MACVLAN
+ build_info
    + artifact_dir - the directory where to download all source and generated configuration (i.e. /tmp)
    + reboot_timeout - the number of seconds to wait for the hosts to be imaged
+ docker
    + repo_host - the name of the node used as a local cache to the Docker images
    + repo_pass - the password to the local repository
+ proxies - To be used by the Configuration node (required)
 also see associated section in the [snaps-kubernetes installation docs](https://github.com/cablelabs/snaps-kubernetes/blob/master/doc/source/install/install.md)
    + ftp_proxy - value or empty string
    + http_proxy - value or empty string
    + https_proxy - value or empty string
    + no_proxy - value or empty string
+ kubespray_proxies - To be used by the master and worker nodes (optional: values used default to 'proxies')
 also see associated section in the [snaps-kubernetes installation docs](https://github.com/cablelabs/snaps-kubernetes/blob/master/doc/source/install/install.md)
    + http_proxy - value or empty string
    + https_proxy - value or empty string
+ Persistent_Volumes - please see associated section in the [snaps-kubernetes installation docs](https://github.com/cablelabs/snaps-kubernetes/blob/master/doc/source/install/install.md)
+ Networks - please see associated section in the [snaps-kubernetes installation docs](https://github.com/cablelabs/snaps-kubernetes/blob/master/doc/source/install/install.md)
+ secrets - please see associated section in the [snaps-kubernetes installation docs](https://github.com/cablelabs/snaps-kubernetes/blob/master/doc/source/install/install.md)

#### Post Script
Review the post script file at: adrenaline/adrenaline/deployment/boot/post_script to see if any changes are required for your environment (e.g., gpu device id if you use a different GPU device than provided in the script.)
Make changes as needed before installing.

### Install

Run `launch.py` as shown below:

```
python $PWD/launch.py -b {path to boot config} -k {path to k8s template} -t deploy_all
```

##### Program Arguments
+ -b - the full path to the boot template/config file
+ -k - the full path to the adrenaline/k8s template/config file
+ -e - optional environment to be applied by Jinga2 to the boot and adrenaline files
+ -t - the task to perform
    * deploy_all - images nodes, installs hardware drivers, Kubernetes, and hardware K8s plugins
    * deploy_boot - images nodes, installs hardware drivers
    * deploy_k8s - Kubernetes and hardware K8s plugins
    * clean_all - cleans nodes of Kubernetes and Docker and removes DRP from the Configuration server
    * clean_boot - removes DRP from Configuration server
    * clean_k8s - cleans nodes of Kubernetes and Docker
+ -o - generally only used by CI when testing on OpenStack with snaps-orchestration
+ -l - log level (INFO|DEBUG)

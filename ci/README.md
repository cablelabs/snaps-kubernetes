
# Continuous Integration ReadMe

## 1 Introduction

This document serves as a guide for executing the iaas_launch.py
during development or within a Continuous Integration (CI) environment.
These scripts help to increase agility and speed of development by not
having to depend on scarce hardware resources on which to test the code,
which ultimately helps to increase overall stability. In addition to
exercising the code, these scripts can also help serve as a concrete
example on how to configure and execute snaps-kubernetes on a baremetal
rack.

The scripts under the ci directory are responsible for creating the
minimal compute, networking and storage resources required to
execute iaas_launch.py within an OpenStack environment. Of the three
virtual machines spawned, one will serve as the build machine on which
iaas_launch.py will be executed and two targets that will ultimately
become single Kubernetes master and single minion nodes with a single
network interface.

### Terms and Conventions

The terms and typographical conventions used in this document are listed and
explained in below table.

| Convention | Usage |
| ---------- | ----- |
| CI Server | This is the physical or virtual server where we run the CI script. The CI server will connect to an OpenStack instance to create the environment|
| Build Server | The VM which will install snaps-openstack |
| master | The Kubernetes controller node. |
| minion | The Kubernetes compute node. |

### Acronyms

The acronyms expanded below are fundamental to the information in this
document.

| Acronym | Explanation |
| ------- | ----------- |
| CI | Continuous Integratoin |
| VM | Virtual Machine |

## Setup & Execution

### Download and install snaps-oo.
```
git clone https://gerrit.opnfv.org/gerrit/snaps
sudo apt update
sudo apt install python git python2.7-dev libssl-dev python-pip
sudo pip install -e snaps/snaps
```

### Configure the environment file.
Please begin with the file ci/snaps/snaps-env.yaml.tmplt. Below is a
short explanation of each variable:

* build_id - Used for appending to the names of any shared OpenStack resources being spawned by this process
* k8s_version - Kubernetes version to lay down (default 1.13.3). Do not prefix with 'v'
* admin_user - The name of an OpenStack user that is part of the 'admin' group
* admin_proj - The name of an OpenStack project that has been associated with the 'admin_user'
* admin_pass - The associated OpenStack password for the 'admin_user'
* auth_url - The OpenStack pod's auth URL
* id_api_version - The OpenStack pod's identity services version (generally should be '3')
* build_kp_pub_path - The location where the existing public key or where one will be created that will be injected into the build VM
* build_kp_pub_path - The location where the existing private key or where one will be created that will be used to SSH into the build VM
* ext_net - The OpenStack pod's external network name used for external routing and floating IPs
* branch_name - The snaps-kubernetes git branch to use (generally should be 'master')
* node_host_pass - The 'root' password assigned to the target nodes
* os_user_pass - The password assigned to the OpenStack user created by the CI scripts
* src_copy_dir - The directory on the build VM on which to copy the source code
* ctrl_ip_prfx - The IPv4 prefix for the build VM's overlay network for floating IP SSH access (e.g. '10.0.0')
* admin_ip_prfx - The IPv4 prefix for the network to be used by Kubernetes (e.g. '10.1.0')
* admin_iface - 'ens3' must be the value with the image being used (TODO - consider removing this configuration option as it is directly tied to the ubuntu image)
* deployment_yaml_target_path - The location where to copy the deployment.yaml file (TODO - consider removing this configuration option as it really does not have to be configurable)
* local_snaps_k8_dir - The location to the local snaps-kubernetes source directory which will be copied to the build VM
* flavor_metadata - snaps-oo formatted flavor extra metadata generally used for CPU pinning in this context
* run_build - When True, deployment operations will be executed (default True)
* run_validation - When True, validation operations will be executed (default True)
* run_conformance - When True, the CNCF tests will be setup and executed on the build server (default False). Note: script will exit after CNCF has been installed and kicked-off but will not wait for completion which is ~ 2 hours
* inject_keys - Denotes whether or not the CI scripts should inject ssh keys into the new VMs prior to executing the iaas_launch.py script

### Launch
note: The entire process can take up to an hour to complete.
```
python { path_to_snaps-oo}/examples/launch.py -t { path_to_snaps-kubernetes}/ci/snaps/snaps_k8_tmplt.yaml \
-e { path_to_env_file } -d
```

### Cleanup
This will remove all OpenStack objects.
```
python { path_to_snaps-oo}/examples/launch.py -t { path_to_snaps-kubernetes}/ci/snaps/snaps_k8_tmplt.yaml \
-e { path_to_env_file } -c
```

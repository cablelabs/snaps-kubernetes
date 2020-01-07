# Adrenaline

Adrenaline is part of the SNAPS<sup>TM</sup> Program we are developing at
[CableLabs](http://cablelabs.com/) to automate the installation of an open 
hardware platform with accelerators, including GPU and FPGA cards. It leverages
[SNAPS-Boot](https://github.com/cablelabs/snaps-boot),
[SNAPS-Kubernetes](https://github.com/cablelabs/snaps-kubernetes) and
[Kubernetes device plug-ins](https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/device-plugins/)
to provide an easy-to-install platform where hardware accelerators can be
automatically configured and managed in a containerized environment and 
utilized by operators in many applications. 

# How to Deploy
## Set up build node
On a build node (physical or virtual) that has access to the target cluster, 
install Ubuntu 18.04 on it.

## Install prerequisites on build node
Clone the git repository https://github.com/cablelabs/snaps-kubernetes. If you
need access, please send an email to: [snaps@cablelabs.com](mailto:snaps@cablelabs.com).

## Update configuration files for the environment
Copy <repo_dir>/adrenaline/conf/sample_hosts.yaml to another file (e.g., 
<home_dir>/conf/hosts.yaml) and make changes according to your environment, 
including server MAC addresses, networking interface names, gateways, 
IP addresses, domain name, credentials, and proxy settings (if applicable).

Copy <repo_dir>/adrenaline/conf/sample_k8s.yaml to another file (e.g., 
<home_dir>/conf/k8s.yaml) and make changes according to your environment, 
including private key file name, networking interface names, artifact file 
location, and credentials for docker hub.

## Check post script file
Review <repo_dir>/adrenaline/adrenaline/deployment/boot/post_script file 
content, and make changes as needed in order to run the desired post script 
steps.

## Run the deployment command
Deploy the cluster. Since the command will PXE boot and install ubuntu 18.04, 
execute post script, and deploy kubernetes on the cluster, it will last more 
than one hour. We suggest you use screen session for the command below so that
it won't be accidentally interrupted.
```bash
sudo python <repo_dir>/adrenaline/launch.py -b <home_dir>/conf/hosts.yaml \
-k <home_dir>/conf/k8s.yaml -t deploy_all 2>&1 |tee ~/deploy.log
```
## Cleanup
In case you want to perform cleanup (e.g., after a failure), use the following 
command:
```bash
sudo python <repo_dir>/adrenaline/launch.py -b <home_dir>/conf/hosts.yaml \
-k <home_dir>/conf/k8s.yaml -t clean_all 2>&1 |tee ~/cleanup.log
```
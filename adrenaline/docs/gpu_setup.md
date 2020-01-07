# GPU Support

As adrenaline is responsible for laying down all components necessary
for running container workloads on a rack of servers, it is also capable of
installing the necessary components for allowing containers to access NVIDIA
GPU resources.
(note: The following processes will reboot the server a couple of times. Should
Kubernetes not come back up, check to ensure that swap is set to off on the
node in question. When swap is 'on' the Kubernetes daemon 'kubelet' may not
restart making that node unavailable to the cluster)

# Boot
After the Ubuntu operating system has been installed on cluster nodes, the
necessary packages for the NVIDIA kernel modules are installed via apt prior
to a reboot.

1. curl
1. software-properties-common
1. nfs-common
1. libcuda1-384
1. nvidia-utils-390

Please see the exact operations in
adrenaline/adrenaline/playbooks/boot/setup_gpu.yaml

# Docker
After snaps-kubernetes has completed installing Docker and Kubernetes, the
following operations take place on worker nodes containing GPUs that will allow
Docker access the GPUs:

Setup apt
1. add the apt-key from https://nvidia.github.io/nvidia-docker/gpgkey
1. add the repo https://nvidia.github.io/nvidia-docker/$(. /etc/os-release;echo $ID$VERSION_ID)/nvidia-docker.list
1. apt update

Install
1. nvidia-container-runtime=2.0.0+docker18.06.1-1
1. nvidia-docker2=2.0.3+docker18.06.1-1 

Configure Docker
1. Replaces /etc/docker/daemon.json with adrenaline/adrenaline/playbooks/kubernetes/daemon.json
2. reboot server

Please see the exact operations in
adrenaline/adrenaline/playbooks/kubernetes/setup_gpu_docker.yaml

# Kubernetes
After Docker has been setup, it is time to let Kubernetes know that the cluster
has nodes with availale GPUs. This is done by using the kubectl client to
install the nvidia-device-plugin:

1. kubectl create -f https://raw.githubusercontent.com/NVIDIA/k8s-device-plugin/master/nvidia-device-plugin.yml

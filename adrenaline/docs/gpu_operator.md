# NVIDIA GPU Operator

NVIDIA has developed software using the [Operator pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/). The code is available [here](https://github.com/NVIDIA/gpu-operator) and the documentation is available [here](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/overview.html). The NVIDIA GPU Operator will work on SNAPS™-Kubernetes.

The basic installation steps are:

1. Install the operator.

Note that it is important that the NVIDA drivers are **not** installed on the worker node that hosts the NVIDIA GPU card. See the [getting started](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/getting-started.html#) section for more information.


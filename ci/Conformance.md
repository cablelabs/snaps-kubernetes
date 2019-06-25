# Conformance results

## To check for the existing nodes
```
$ kubectl get nodes
```

## Recommended host machine configuration:
1. RAM   : 32 GB
1. vCPUs : 8  

## Heptio Sonobuoy test
The standard tool for running the conformance tests, Sonobuoy, is already installed while deploying the kubernetes cluster using snaps-orchestration.

### Install Sonobuoy
1. For the latest version of CLI:
```
$ go get -u -v github.com/heptio/sonobuoy
```
2. For a specific version x of Sonobuoy:
```
$ wget {https://github.com/heptio/sonobuoy/releases/download/{version}/{version x tarball}}
$ tar -xvzf {version x tarball}
```
### Run Sonobuoy
```
$ ./sonobuoy run --mode={optional flag quick or wait}
flag = quick runs a single test to quickly validate the cluster configuration;
default flag = wait
```
### View actively running pods
```
$ ./sonobuoy status
```
### Inspect the logs
```
$ ./sonobuoy logs
```
### View the status of the running sonobuoy pods
```
$ kubectl -n heptio-sonobuoy get all
```
### Get all pods
```
$ kubectl get po --all-namespaces
```
### Verify that Sonobuoy has completed successfully, check the logs
```
$ kubectl logs -f sonobuoy --namespace=heptio-sonobuoy
```
The logs will display the following message on successful completion of the Sonobuoy test: 
```
msg="no-exit was specified, sonobuoy is now blocking"
``` 
### Retrieve the results 
```
$ ./sonobuoy retrieve
$ tar -xvzf {tarball}
```
Note: Make sure to give enough time for the tests to complete successfully; Trying to retrieve the result too soon will generate result with missing log files.
### Delete pods and namespaces
```
$ ./sonobuoy delete --all
```
## Submit Conformance results
Refer to the following link:
<https://github.com/cncf/k8s-conformance/blob/master/instructions.md#uploading>

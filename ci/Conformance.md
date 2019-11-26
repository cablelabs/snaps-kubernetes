# Conformance Testing
To get the underlying platform as Kubernetes certified, a set of Conformance tests available from Heptio Sonobuoy are executed over the platform. The steps are as follows:
1. Deploy the cluster
2. Install Sonobuoy client
3. Run the Sonobuoy test
4. Retrieve the results
5. Prepare a PR as per instructions on k8s Conformance
6. Upload the results
7. Integrate reviews from the PR
8. Get certified once the PR is merged

## Recommended host machine configuration
RAM   : 32 GB

vCPUs : 8  

## Heptio Sonobuoy test
The standard tool for running the conformance tests, Sonobuoy, is pre-installed on the build server while deploying the kubernetes cluster using snaps-orchestration.

Default version installed: Sonobuoy v0.14.3.

### Install Sonobuoy
Install the latest version of go and fetch the latest version of sonobuoy CLI:
```bash
go get -u -v github.com/heptio/sonobuoy
```
For a specific version x of Sonobuoy:
```bash
wget {https://github.com/heptio/sonobuoy/releases/download/{version}/{version x tarball}}
tar -xvzf {version x tarball}
```
Note: snaps-orchestration installs Sonobuoy v0.14.3. The latest version of Sonobuoy was found to be unstable because the server did not necessarily give enough time for the pods to execute and it ran into a timeout error giving incomplete results.
### Run Sonobuoy
```bash
./sonobuoy run --kubeconfig=/tmp/snaps-k8s-projects/{{ project_name }}/node-kubeconfig.yaml --{optional flag quick or wait}
flag = quick, runs a single test to quickly validate the cluster configuration
default flag = wait
```
Note: Make sure to configure /tmp/snaps-k8s-projects/{{ project_name }}/node-kubeconfig.yaml file.
### View actively running pods
```bash
./sonobuoy status
```
### Inspect the logs
```bash
./sonobuoy logs
```
The logs will display the following message on successful completion of the Sonobuoy test:
```bash
msg="no-exit was specified, sonobuoy is now blocking"
```
### Retrieve the results
```bash
./sonobuoy retrieve
tar -xvzf {tarball}
```
The log files required by the CNCF while submitting the conformance results can be found as follows:
```bash
/{tarball folder}/plugins/e2e/e2e.log
/{tarball folder}/plugins/e2e/junit.xml
```
Note: Make sure to give enough time for the tests to complete successfully; Trying to retrieve the result too soon will generate results with missing log files.
### Delete pods and namespaces
```bash
./sonobuoy delete --all
```
## Submit Conformance results
Refer to the following link:
<https://github.com/cncf/k8s-conformance/blob/master/instructions.md#uploading>

## Conformance results for SNAPS-Kubernetes
<https://github.com/cablelabs/k8s-conformance/tree/master/v1.15/snaps-kubernetes>

Note: README.md and PRODUCT.yaml can be copied and updated as needed.

To stage the updates, refer to the following link:
<https://github.com/cablelabs/k8s-conformance>

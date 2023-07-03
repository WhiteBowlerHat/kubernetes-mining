# Theme 1 : Introrduction to Kubernetes
Kubernetes documentation
## Kubernetes cluster
## Basic tools
# Theme 2 : Kubernetes Management
## Tools
# Theme 3 : Kubernetes Security
## Tools

### Detection

* [falco](https://github.com/falcosecurity/falco)
* [tetragon](https://github.com/cilium/tetragon)
* [sysdig](https://github.com/draios/sysdig)
* [tracee](https://github.com/aquasecurity/tracee)
* [security-guard](https://github.com/knative-sandbox/security-guard)

### Hardening

* [seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/) - "can be used to sandbox the privileges of a process, restricting the calls it is able to make from userspace into the kernel."
* [AppArmor](https://kubernetes.io/docs/tutorials/security/apparmor/) - "AppArmor is a Linux kernel security module that supplements the standard Linux user and group based permissions to confine programs to a limited set of resources. AppArmor can be configured for any application to reduce its potential attack surface and provide greater in-depth defense."
* [Kubernetes Network Policy Recipes](https://github.com/ahmetb/kubernetes-network-policy-recipes)

### Simulation / Experimentation

* [Stratus Red Team](https://github.com/DataDog/stratus-red-team) - Stratus Red Team is "Atomic Red Team™" for the cloud, allowing to emulate offensive attack techniques in a granular and self-contained manner.
  * see [Kubernetes Attacks](https://github.com/DataDog/stratus-red-team/blob/main/docs/attack-techniques/kubernetes/index.md)
* [falcosecurity/event-generator](https://github.com/falcosecurity/event-generator)
* [minikube](https://github.com/kubernetes/minikube) - minikube implements a local Kubernetes cluster on macOS, Linux, and Windows. minikube's primary goals are to be the best tool for local Kubernetes application development and to support all Kubernetes features that fit.
* [controlplaneio/simulator](https://github.com/controlplaneio/simulator)
* [kubernetes-goat](https://github.com/madhuakula/kubernetes-goat)
* [Sock Shop: A Microservices Demo Application](https://microservices-demo.github.io/)

### Attack

* [kubesploit](https://github.com/cyberark/kubesploit)
* [Falco-bypasses](https://github.com/blackberry/Falco-bypasses)
* [go-pillage-registries](https://github.com/nccgroup/go-pillage-registries)
* [ConMachi](https://github.com/nccgroup/ConMachi)
* [peirates](https://github.com/inguardians/peirates)
* [botb](https://github.com/brompwnie/botb)
* [kubernetes-info.nse script](https://gist.github.com/jpts/5d23bfd9b8cc08e32a3591c8195482a8)
* [kube-hunter](https://github.com/aquasecurity/kube-hunter)

### Misc

* [kube-iptables-tailer](https://github.com/box/kube-iptables-tailer)
* [inspektor-gadget](https://github.com/inspektor-gadget/inspektor-gadget)


## Detection Rules and Analytics

* [Elastic kubernetes detection rules ](https://github.com/elastic/detection-rules/tree/main/rules/integrations/kubernetes)
* [Falco Rules](https://github.com/falcosecurity/rules)
* [Panther Labs gcp_k8s_rules](https://github.com/panther-labs/panther-analysis/tree/master/rules/gcp_k8s_rules)
* [Sigma cloud/azure/kube*.yml](https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/azure)
* [Sigma cloud/gcp/kube*.yml](https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/gcp)
* [Splunk Analytic Story: Kubernetes Scanning Activity](https://research.splunk.com/stories/kubernetes_scanning_activity/) 
* [Splunk Analytic Story: Kubernetes Sensitive Object Access Activity](https://research.splunk.com/stories/kubernetes_sensitive_object_access_activity/) 
* [Tracee Signatures](https://github.com/aquasecurity/tracee/tree/main/signatures)
* Projectdiscovery/nuclei-templates 
  * [technologies/kubernetes](https://github.com/projectdiscovery/nuclei-templates/tree/main/technologies/kubernetes)
  * [exposed-panels/kube*.yaml](https://github.com/projectdiscovery/nuclei-templates/tree/main/exposed-panels)
  * [misconfiguration/kubernetes](https://github.com/projectdiscovery/nuclei-templates/tree/main/misconfiguration/kubernetes)
  * [exposures/configs/kube*.yaml](https://github.com/projectdiscovery/nuclei-templates/tree/main/exposures/configs)

This list of tool has been established by using different sources:
* https://github.com/jatrost/awesome-kubernetes-threat-detection


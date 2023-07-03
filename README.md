# Theme 1 : Introrduction to Kubernetes
Kubernetes documentation
## Kubernetes cluster
## Basic tools
# Theme 2 : Kubernetes Management
## Tools
# Theme 3 : Kubernetes Security
## Guides

* [CIS Benchmarks](https://downloads.cisecurity.org/#/)
* [KStig](https://ncp.nist.gov/checklist/996)
* [NSA Recommendations](https://www.cisa.gov/news-events/alerts/2022/03/15/updated-kubernetes-hardening-guide)
* 
## TTPs / Attack Matrices

* [MITRE ATT&CK Containers Matrix](https://attack.mitre.org/matrices/enterprise/containers/)
* [Threat matrix for Kubernetes](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/) 
* [Secure containerized environments with updated threat matrix for Kubernetes](https://www.microsoft.com/en-us/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/)
* [OWASP Kubernetes Top 10](https://owasp.org/www-project-kubernetes-top-ten/)
* [OWASP Kubernetes Top 10 (Sysdig)](https://sysdig.com/blog/top-owasp-kubernetes/)
* [AVOLENS Kubernetes Threat Matrix](https://kubernetes-security.de/en/kubernetes_threat_matrix/#kubernetes-threat-matrix)
  
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

### Audit
* [KubiScan](https://github.com/cyberark/KubiScan) (Custom version : https://github.com/WhiteBowlerHat/KubiScan)
* [Checkov](https://github.com/bridgecrewio/checkov)
* [kube-linter](https://github.com/stackrox/kube-linter)
* [Terrascan](https://github.com/tenable/terrascan)

### Misc

* [kube-iptables-tailer](https://github.com/box/kube-iptables-tailer)
* [inspektor-gadget](https://github.com/inspektor-gadget/inspektor-gadget)

This list of tool has been established by using different sources:
* https://github.com/jatrost/awesome-kubernetes-threat-detection


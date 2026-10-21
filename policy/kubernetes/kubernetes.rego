# Admission-style rules for rendered Kubernetes manifests.
# Run with: kubectl kustomize deploy/k8s | conftest test --policy policy/kubernetes -
package main

import rego.v1

workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "Job"}

pod_spec := input.spec.template.spec if input.kind in workload_kinds

pod_spec := input.spec.jobTemplate.spec.template.spec if input.kind == "CronJob"

containers contains c if some c in pod_spec.containers

containers contains c if some c in pod_spec.initContainers

name := input.metadata.name

# --- identity and privileges -----------------------------------------------------------

runs_as_non_root(c) if c.securityContext.runAsNonRoot == true

runs_as_non_root(c) if {
	not c.securityContext.runAsNonRoot == false
	pod_spec.securityContext.runAsNonRoot == true
}

deny contains msg if {
	some c in containers
	not runs_as_non_root(c)
	msg := sprintf("%s/%s: container %q must set runAsNonRoot: true", [input.kind, name, c.name])
}

deny contains msg if {
	some c in containers
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("%s/%s: container %q must set allowPrivilegeEscalation: false", [input.kind, name, c.name])
}

deny contains msg if {
	some c in containers
	c.securityContext.privileged == true
	msg := sprintf("%s/%s: container %q must not be privileged", [input.kind, name, c.name])
}

deny contains msg if {
	some c in containers
	not c.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("%s/%s: container %q must use a read-only root filesystem", [input.kind, name, c.name])
}

deny contains msg if {
	some c in containers
	not "ALL" in object.get(c, ["securityContext", "capabilities", "drop"], [])
	msg := sprintf("%s/%s: container %q must drop ALL capabilities", [input.kind, name, c.name])
}

deny contains msg if {
	some c in containers
	some cap in object.get(c, ["securityContext", "capabilities", "add"], [])
	msg := sprintf("%s/%s: container %q must not add capability %s", [input.kind, name, c.name, cap])
}

seccomp_runtime_default(c) if c.securityContext.seccompProfile.type == "RuntimeDefault"

seccomp_runtime_default(_) if pod_spec.securityContext.seccompProfile.type == "RuntimeDefault"

deny contains msg if {
	some c in containers
	not seccomp_runtime_default(c)
	msg := sprintf("%s/%s: container %q must use the RuntimeDefault seccomp profile", [input.kind, name, c.name])
}

deny contains msg if {
	pod_spec
	not pod_spec.automountServiceAccountToken == false
	msg := sprintf("%s/%s: pod must set automountServiceAccountToken: false", [input.kind, name])
}

# --- host isolation --------------------------------------------------------------------

deny contains msg if {
	some field in ["hostNetwork", "hostPID", "hostIPC"]
	pod_spec[field] == true
	msg := sprintf("%s/%s: pod must not use %s", [input.kind, name, field])
}

deny contains msg if {
	some v in pod_spec.volumes
	v.hostPath
	msg := sprintf("%s/%s: hostPath volume %q is not allowed", [input.kind, name, v.name])
}

# --- supply chain ----------------------------------------------------------------------

image_is_pinned(image) if contains(image, "@sha256:")

image_is_pinned(image) if {
	not contains(image, "@")
	parts := split(image, "/")
	last := parts[count(parts) - 1]
	contains(last, ":")
	not endswith(last, ":latest")
}

deny contains msg if {
	some c in containers
	not image_is_pinned(c.image)
	msg := sprintf("%s/%s: container %q image %q must use a fixed tag or digest, never latest", [input.kind, name, c.name, c.image])
}

# --- availability ----------------------------------------------------------------------

deny contains msg if {
	some c in containers
	some resource in ["cpu", "memory"]
	not c.resources.limits[resource]
	msg := sprintf("%s/%s: container %q must set a %s limit", [input.kind, name, c.name, resource])
}

deny contains msg if {
	some c in containers
	some resource in ["cpu", "memory"]
	not c.resources.requests[resource]
	msg := sprintf("%s/%s: container %q must set a %s request", [input.kind, name, c.name, resource])
}

deny contains msg if {
	some c in pod_spec.containers
	some probe in ["livenessProbe", "readinessProbe"]
	not c[probe]
	msg := sprintf("%s/%s: container %q must define a %s", [input.kind, name, c.name, probe])
}

# --- namespaces and exposure -------------------------------------------------------------

deny contains msg if {
	input.kind == "Namespace"
	not input.metadata.labels["pod-security.kubernetes.io/enforce"] == "restricted"
	msg := sprintf("Namespace/%s: must enforce the restricted Pod Security Standard", [name])
}

deny contains msg if {
	input.kind == "Service"
	input.spec.type in {"NodePort", "LoadBalancer"}
	msg := sprintf("Service/%s: must stay internal (ClusterIP); expose it through an ingress", [name])
}

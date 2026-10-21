package main

import rego.v1

hardened_container := {
	"name": "api",
	"image": "ghcr.io/example/api:1.2.3",
	"securityContext": {
		"allowPrivilegeEscalation": false,
		"readOnlyRootFilesystem": true,
		"capabilities": {"drop": ["ALL"]},
	},
	"resources": {
		"requests": {"cpu": "50m", "memory": "64Mi"},
		"limits": {"cpu": "500m", "memory": "256Mi"},
	},
	"livenessProbe": {"httpGet": {"path": "/healthz", "port": 8000}},
	"readinessProbe": {"httpGet": {"path": "/readyz", "port": 8000}},
}

deployment(container) := {
	"kind": "Deployment",
	"metadata": {"name": "api"},
	"spec": {"template": {"spec": {
		"automountServiceAccountToken": false,
		"securityContext": {"runAsNonRoot": true, "seccompProfile": {"type": "RuntimeDefault"}},
		"containers": [container],
	}}},
}

test_hardened_deployment_passes if {
	count(deny) == 0 with input as deployment(hardened_container)
}

test_root_container_is_denied if {
	c := object.union(hardened_container, {"securityContext": object.union(
		hardened_container.securityContext,
		{"runAsNonRoot": false},
	)})
	some msg in deny with input as deployment(c)
	contains(msg, "runAsNonRoot")
}

test_privileged_container_is_denied if {
	c := object.union(hardened_container, {"securityContext": object.union(
		hardened_container.securityContext,
		{"privileged": true},
	)})
	some msg in deny with input as deployment(c)
	contains(msg, "must not be privileged")
}

test_latest_tag_is_denied if {
	c := object.union(hardened_container, {"image": "nginx:latest"})
	some msg in deny with input as deployment(c)
	contains(msg, "never latest")
}

test_untagged_image_is_denied if {
	c := object.union(hardened_container, {"image": "registry:5000/nginx"})
	some msg in deny with input as deployment(c)
	contains(msg, "never latest")
}

test_digest_pinned_image_passes if {
	c := object.union(hardened_container, {"image": "nginx@sha256:0123456789abcdef"})
	count(deny) == 0 with input as deployment(c)
}

test_added_capability_is_denied if {
	c := object.union(hardened_container, {"securityContext": object.union(
		hardened_container.securityContext,
		{"capabilities": {"drop": ["ALL"], "add": ["NET_ADMIN"]}},
	)})
	some msg in deny with input as deployment(c)
	contains(msg, "NET_ADMIN")
}

test_missing_limits_are_denied if {
	c := object.remove(hardened_container, ["resources"])
	some msg in deny with input as deployment(c)
	contains(msg, "memory limit")
}

test_host_network_is_denied if {
	d := deployment(hardened_container)
	spec := object.union(d.spec.template.spec, {"hostNetwork": true})
	some msg in deny with input as {"kind": "Deployment", "metadata": d.metadata, "spec": {"template": {"spec": spec}}}
	contains(msg, "hostNetwork")
}

test_namespace_without_pod_security_is_denied if {
	some msg in deny with input as {"kind": "Namespace", "metadata": {"name": "apps", "labels": {}}}
	contains(msg, "restricted Pod Security")
}

test_loadbalancer_service_is_denied if {
	some msg in deny with input as {"kind": "Service", "metadata": {"name": "api"}, "spec": {"type": "LoadBalancer"}}
	contains(msg, "must stay internal")
}

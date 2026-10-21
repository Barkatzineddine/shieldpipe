package main

import rego.v1

instr(cmd, value) := {"Cmd": cmd, "Value": [value], "Original": sprintf("%s %s", [upper(cmd), value])}

good := [
	instr("from", "python:3.12-slim@sha256:abc"),
	instr("user", "10001:10001"),
	instr("healthcheck", "CMD true"),
]

test_hardened_dockerfile_passes if {
	count(deny) == 0 with input as good
}

test_unpinned_base_is_denied if {
	bad := array.concat([instr("from", "python:3.12-slim")], array.slice(good, 1, 3))
	some msg in deny with input as bad
	contains(msg, "pinned by digest")
}

test_missing_user_is_denied if {
	bad := [good[0], good[2]]
	some msg in deny with input as bad
	contains(msg, "non-root USER")
}

test_root_user_is_denied if {
	bad := array.concat(good, [instr("user", "root")])
	some msg in deny with input as bad
	contains(msg, "must not be root")
}

test_add_is_denied if {
	bad := array.concat(good, [instr("add", "https://example.com/tool.tgz /opt/")])
	some msg in deny with input as bad
	contains(msg, "COPY instead of ADD")
}

test_curl_pipe_sh_is_denied if {
	bad := array.concat(good, [instr("run", "curl -fsSL https://get.example.com | sh")])
	some msg in deny with input as bad
	contains(msg, "piping a download")
}

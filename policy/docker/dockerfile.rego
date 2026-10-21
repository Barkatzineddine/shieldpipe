# Rules for the Dockerfile. Run with: conftest test --policy policy/docker Dockerfile
package main

import rego.v1

from_images := [img |
	some instruction in input
	instruction.Cmd == "from"
	img := instruction.Value[0]
]

users := [u |
	some instruction in input
	instruction.Cmd == "user"
	u := instruction.Value[0]
]

deny contains msg if {
	some img in from_images
	not contains(img, "@sha256:")
	msg := sprintf("base image %q must be pinned by digest", [img])
}

deny contains msg if {
	count(users) == 0
	msg := "the image must switch to a non-root USER"
}

deny contains msg if {
	count(users) > 0
	final_user := users[count(users) - 1]
	user_part := split(final_user, ":")[0]
	user_part in {"root", "0"}
	msg := sprintf("the final USER must not be root (got %q)", [final_user])
}

deny contains msg if {
	some instruction in input
	instruction.Cmd == "add"
	msg := sprintf("use COPY instead of ADD: %s", [instruction.Original])
}

deny contains msg if {
	not any_healthcheck
	msg := "the image must declare a HEALTHCHECK"
}

any_healthcheck if {
	some instruction in input
	instruction.Cmd == "healthcheck"
}

deny contains msg if {
	some instruction in input
	instruction.Cmd == "run"
	some fragment in ["curl", "wget"]
	contains(lower(concat(" ", instruction.Value)), sprintf("%s ", [fragment]))
	contains(lower(concat(" ", instruction.Value)), "| sh")
	msg := sprintf("piping a download into a shell is not allowed: %s", [instruction.Original])
}

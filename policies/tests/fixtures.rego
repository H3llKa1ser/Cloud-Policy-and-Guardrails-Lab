# Builders for synthetic plan JSON used by the policy unit tests.
package fixtures

import rego.v1

# A resource change. `module` is "" for the root module.
rc_in(module, type, name, after) := r if {
	module == ""
	r := {
		"address": sprintf("%s.%s", [type, name]),
		"mode": "managed",
		"type": type,
		"name": name,
		"change": {"actions": ["create"], "after": after, "after_unknown": {}},
	}
} else := {
	"address": sprintf("%s.%s.%s", [module, type, name]),
	"module_address": module,
	"mode": "managed",
	"type": type,
	"name": name,
	"change": {"actions": ["create"], "after": after, "after_unknown": {}},
}

rc(type, name, after) := rc_in("", type, name, after)

with_unknown(r, unknown) := object.union(r, {"change": object.union(r.change, {"after_unknown": unknown})})

with_actions(r, actions) := object.union(r, {"change": object.union(r.change, {"actions": actions})})

# Configuration resource whose `attr_name` references `target_type.target_name`.
cfg_ref(type, name, attr_name, target_type, target_name) := {
	"address": sprintf("%s.%s", [type, name]),
	"type": type,
	"name": name,
	"expressions": {attr_name: {"references": [
		sprintf("%s.%s.id", [target_type, target_name]),
		sprintf("%s.%s", [target_type, target_name]),
	]}},
}

plan(rcs) := {"resource_changes": rcs, "configuration": {"root_module": {"resources": []}}}

plan_cfg(rcs, root_cfg) := {"resource_changes": rcs, "configuration": {"root_module": root_cfg}}

# Rule IDs present in a set of "[ID] address: message" strings.
ids(msgs) := {substring(m, 1, indexof(m, "]") - 1) | some m in msgs}

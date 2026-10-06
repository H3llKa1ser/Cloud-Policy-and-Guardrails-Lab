# Shared helpers for evaluating `terraform show -json` plan output.
#
# Every domain policy builds on these so that rules stay short and readable,
# and so plan-format quirks (unknown values, module nesting, count/for_each
# instance keys) are handled in exactly one place.
package lib.tf

import rego.v1

# ---------------------------------------------------------------------------
# Resource selection
# ---------------------------------------------------------------------------

# All managed resources in the plan, whatever their action (incl. no-op).
managed contains rc if {
	some rc in input.resource_changes
	rc.mode == "managed"
}

# Resources this plan will create or update. Policies only judge these:
# deleting a non-compliant resource should never be blocked.
changes contains rc if {
	some rc in managed
	some action in rc.change.actions
	action in {"create", "update"}
}

# Changed resources of one type.
resources(type) := {rc | some rc in changes; rc.type == type}

# Changed resources of any type in a set.
resources_of(types) := {rc | some rc in changes; rc.type in types}

# ---------------------------------------------------------------------------
# Attribute access
# ---------------------------------------------------------------------------

after(rc) := object.get(rc.change, "after", {})

after_unknown(rc) := object.get(rc.change, "after_unknown", {})

# Value of an attribute after apply, or `default_value` when it is null/absent.
attr(rc, name, default_value) := v if {
	v := after(rc)[name]
	v != null
} else := default_value

# True when an attribute will hold a value after apply: either it is known
# now, or Terraform reports it as "known after apply" (e.g. it references a
# KMS key created in the same plan).
is_set(rc, name) if {
	v := after(rc)[name]
	v != null
	v != ""
}

is_set(rc, name) if after_unknown(rc)[name] == true

# Nested blocks are lists in plan JSON. Return the first block or {}.
first_block(rc, name) := b if {
	blocks := after(rc)[name]
	is_array(blocks)
	count(blocks) > 0
	b := blocks[0]
} else := {}

# ---------------------------------------------------------------------------
# Configuration lookup (for "resource X must have companion Y" rules)
#
# Values that reference not-yet-created resources are unknown in
# resource_changes, so we follow the *references* recorded in the
# configuration section instead.
# ---------------------------------------------------------------------------

# module.app["eu"].module.bucket[0] -> ["app", "bucket"]
module_names(rc) := [] if {
	not rc.module_address
} else := names if {
	stripped := regex.replace(rc.module_address, `\[[^\]]*\]`, "")
	parts := split(stripped, ".")
	names := [parts[i] | some i in numbers.range(1, count(parts) - 1); i % 2 == 1]
}

# Path from configuration.root_module to the module that declares rc.
config_path(rc) := [] if {
	count(module_names(rc)) == 0
} else := path if {
	names := module_names(rc)
	path := [seg |
		some i in numbers.range(0, (3 * count(names)) - 1)
		seg := ["module_calls", names[floor(i / 3)], "module"][i % 3]
	]
}

config_resource(rc) := r if {
	mod := object.get(input.configuration.root_module, config_path(rc), {})
	some r in object.get(mod, "resources", [])
	r.address == sprintf("%s.%s", [rc.type, rc.name])
}

references(rc, attr_name) := refs if {
	refs := config_resource(rc).expressions[attr_name].references
} else := []

# True if `ref` points at resource `target` (any attribute, any instance key).
refers_to(ref, target) if {
	base := sprintf("%s.%s", [target.type, target.name])
	some prefix in {base, concat("", [base, "."]), concat("", [base, "["])}
	startswith(ref, prefix)
}

same_module(a, b) if object.get(a, "module_address", "") == object.get(b, "module_address", "")

# Is there a resource of `type`, in the same module as `target`, whose
# `attr_name` argument references `target`?
has_companion(target, type, attr_name) if {
	some other in managed
	other.type == type
	same_module(other, target)
	some ref in references(other, attr_name)
	refers_to(ref, target)
}

# ---------------------------------------------------------------------------
# Tags
#
# tags_all (resource tags + provider default_tags) is usually known at plan
# time, but becomes unknown when a provider has no default_tags block. In that
# case we rebuild the effective tags from the provider configuration, so a
# resource cannot dodge tag checks just by using an untagged provider.
# ---------------------------------------------------------------------------

provider_config(rc) := input.configuration.provider_config[config_resource(rc).provider_config_key]

# default_tags built from variables/locals cannot be resolved from the plan.
dynamic_default_tags(rc) if {
	dt := provider_config(rc).expressions.default_tags
	not dt[0].tags.constant_value
}

# The provider's default_tags when statically known, {} when it has none.
default_tags(rc) := t if {
	t := provider_config(rc).expressions.default_tags[0].tags.constant_value
	is_object(t)
} else := {} if {
	not dynamic_default_tags(rc)
}

resource_tags(rc) := t if {
	t := after(rc).tags
	is_object(t)
} else := {}

unknown(rc, name) if object.get(after_unknown(rc), name, false) == true

# Effective tags, or undefined when they cannot be determined at plan time.
tags(rc) := t if {
	not unknown(rc, "tags_all")
	t := after(rc).tags_all
	is_object(t)
} else := t if {
	# Schema without tags_all (or synthetic input): resource tags only.
	not unknown(rc, "tags_all")
	t := resource_tags(rc)
} else := t if {
	# tags_all unknown: resolve provider default_tags from configuration.
	not unknown(rc, "tags")
	provider_config(rc)
	t := object.union(default_tags(rc), resource_tags(rc))
}

# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

# Build a finding from the calling rule's METADATA annotation. The rule ID and
# level live only in the annotation, so a rule without complete metadata can
# never fire (and its unit tests fail): the control catalogue cannot drift
# from the code.
finding(meta, rc, msg) := {
	"id": meta.custom.id,
	"level": meta.custom.level,
	"address": rc.address,
	"msg": msg,
}

format(v) := sprintf("[%s] %s: %s", [v.id, v.address, v.msg])

world_cidrs := {"0.0.0.0/0", "::/0"}

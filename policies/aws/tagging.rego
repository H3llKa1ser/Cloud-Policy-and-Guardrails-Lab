# Tagging guardrails: every taggable resource carries ownership and data
# classification, so findings route to an owner and data handling is clear.
package aws.tagging

import data.lib.exceptions
import data.lib.tf
import rego.v1

required_tags := {"Owner", "Environment", "DataClassification"}

classifications := {"public", "internal", "confidential", "restricted"}

environments := {"dev", "test", "staging", "prod", "lab"}

# A resource is taggable if its schema exposes tags or tags_all.
taggable contains rc if {
	some rc in tf.changes
	some key in {"tags", "tags_all"}
	key in object.keys(tf.after(rc))
}

# METADATA
# title: Required ownership and classification tags are present
# custom:
#   id: TAG_101
#   level: warn
#   severity: low
#   mapping: author
#   controls:
#     nist_800_53_r5: [CM-8]
findings contains f if {
	some rc in taggable
	missing := required_tags - object.keys(tf.tags(rc))
	count(missing) > 0
	f := tf.finding(rego.metadata.rule(), rc, sprintf("missing required tag(s): %s", [concat(", ", sort(missing))]))
}

# METADATA
# title: DataClassification uses the approved vocabulary
# custom:
#   id: TAG_001
#   level: deny
#   severity: medium
#   mapping: author
#   controls:
#     nist_800_53_r5: [CM-8, RA-2]
findings contains f if {
	some rc in taggable
	value := tf.tags(rc).DataClassification
	not value in classifications
	f := tf.finding(rego.metadata.rule(), rc, sprintf("DataClassification %q is not one of %v", [value, sort(classifications)]))
}

# METADATA
# title: Environment uses the approved vocabulary
# custom:
#   id: TAG_002
#   level: deny
#   severity: low
#   mapping: author
#   controls:
#     nist_800_53_r5: [CM-8]
findings contains f if {
	some rc in taggable
	value := tf.tags(rc).Environment
	not value in environments
	f := tf.finding(rego.metadata.rule(), rc, sprintf("Environment %q is not one of %v", [value, sort(environments)]))
}

deny contains tf.format(f) if {
	some f in findings
	f.level == "deny"
	not exceptions.exempt(f.id, f.address)
}

warn contains tf.format(f) if {
	some f in findings
	f.level == "warn"
	not exceptions.exempt(f.id, f.address)
}

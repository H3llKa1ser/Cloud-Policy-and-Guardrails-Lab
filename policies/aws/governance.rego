# Governance of the exception register itself. These rules cannot be
# exempted: an exception process that can be bypassed is not a control.
package aws.governance

import data.lib.exceptions
import rego.v1

# METADATA
# title: Policy exceptions are complete
# custom:
#   id: GOV_001
#   level: deny
#   severity: high
#   mapping: author
#   controls:
#     nist_800_53_r5: [CM-3, RA-7]
deny contains sprintf("[%s] exception %d (%s): missing %s", [rego.metadata.rule().custom.id, i, object.get(e, "rule", "?"), concat(", ", sort(missing))]) if {
	some i, e in exceptions.entries
	missing := exceptions.missing_fields(e)
	count(missing) > 0
}

# METADATA
# title: Policy exceptions expire within the maximum window
# custom:
#   id: GOV_002
#   level: deny
#   severity: high
#   mapping: author
#   controls:
#     nist_800_53_r5: [CM-3, RA-7]
deny contains sprintf("[%s] exception %d (%s): expiry is more than %d days away", [rego.metadata.rule().custom.id, i, e.rule, exceptions.max_days]) if {
	some i, e in exceptions.entries
	count(exceptions.missing_fields(e)) == 0
	exceptions.too_long(e)
}

# METADATA
# title: Expired policy exceptions are removed
# custom:
#   id: GOV_101
#   level: warn
#   severity: low
#   mapping: author
#   controls:
#     nist_800_53_r5: [CM-3]
warn contains sprintf("[%s] exception %d (%s, %s) expired on %s and is ignored", [rego.metadata.rule().custom.id, i, e.rule, e.ticket, e.expires]) if {
	some i, e in exceptions.entries
	count(exceptions.missing_fields(e)) == 0
	exceptions.expired(e)
}

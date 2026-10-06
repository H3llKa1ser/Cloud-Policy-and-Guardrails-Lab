# Time-boxed, auditable policy exceptions.
#
# Exceptions live in exceptions/exceptions.yaml and are loaded with
# `conftest --data exceptions/`. Each one must name a rule, a resource
# address (glob, `*` matches within one address segment), a ticket, a
# justification and an expiry no more than `max_days` away. Invalid or
# expired exceptions suppress nothing; see aws/governance.rego for the
# rules that flag them.
package lib.exceptions

import rego.v1

max_days := 90

ns_per_day := ((24 * 60) * 60) * 1000000000

entries := data.exceptions if {
	is_array(data.exceptions)
} else := []

required_fields := {"rule", "address", "ticket", "justification", "expires"}

missing_fields(e) := {f |
	some f in required_fields
	object.get(e, f, "") == ""
}

expires_ns(e) := time.parse_rfc3339_ns(e.expires)

expired(e) if expires_ns(e) <= time.now_ns()

too_long(e) if expires_ns(e) > time.now_ns() + (max_days * ns_per_day)

valid(e) if {
	count(missing_fields(e)) == 0
	not expired(e)
	not too_long(e)
}

exempt(rule_id, address) if {
	some e in entries
	valid(e)
	e.rule == rule_id
	glob.match(e.address, ["."], address)
}

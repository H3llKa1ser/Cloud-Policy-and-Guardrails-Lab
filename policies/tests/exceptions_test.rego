package exceptions_test

import data.aws.governance
import data.aws.network
import data.fixtures as f
import rego.v1

# 2026-10-01T00:00:00Z
now := 1790812800000000000

open_ssh := f.plan([f.rc_in("module.bastion", "aws_vpc_security_group_ingress_rule", "ssh", {
	"from_port": 22, "to_port": 22, "ip_protocol": "tcp", "cidr_ipv4": "0.0.0.0/0",
})])

exception(overrides) := object.union(
	{
		"rule": "NET_001",
		"address": "module.bastion.aws_vpc_security_group_ingress_rule.ssh",
		"ticket": "SEC-123",
		"justification": "Break-glass bastion during VPN migration",
		"expires": "2026-11-15T00:00:00Z",
	},
	overrides,
)

test_valid_exception_suppresses if {
	count(network.deny) == 0 with input as open_ssh
		with data.exceptions as [exception({})]
		with time.now_ns as now
	count(governance.deny) == 0 with data.exceptions as [exception({})] with time.now_ns as now
}

test_glob_address_matches_within_segments if {
	e := exception({"address": "module.bastion.aws_vpc_security_group_ingress_rule.*"})
	count(network.deny) == 0 with input as open_ssh with data.exceptions as [e] with time.now_ns as now
}

test_glob_does_not_cross_modules if {
	e := exception({"address": "*.aws_vpc_security_group_ingress_rule.ssh"})
	count(network.deny) == 1 with input as open_ssh with data.exceptions as [e] with time.now_ns as now
}

test_exception_for_other_rule_does_not_suppress if {
	e := exception({"rule": "NET_002"})
	count(network.deny) == 1 with input as open_ssh with data.exceptions as [e] with time.now_ns as now
}

test_expired_exception_ignored_and_flagged if {
	e := exception({"expires": "2026-09-01T00:00:00Z"})
	count(network.deny) == 1 with input as open_ssh with data.exceptions as [e] with time.now_ns as now
	f.ids(governance.warn) == {"GOV_101"} with data.exceptions as [e] with time.now_ns as now
}

test_incomplete_exception_ignored_and_denied if {
	e := object.remove(exception({}), ["ticket", "justification"])
	count(network.deny) == 1 with input as open_ssh with data.exceptions as [e] with time.now_ns as now
	governance.deny == {"[GOV_001] exception 0 (NET_001): missing justification, ticket"} with data.exceptions as [e] with time.now_ns as now
}

test_overlong_exception_ignored_and_denied if {
	e := exception({"expires": "2027-06-01T00:00:00Z"})
	count(network.deny) == 1 with input as open_ssh with data.exceptions as [e] with time.now_ns as now
	f.ids(governance.deny) == {"GOV_002"} with data.exceptions as [e] with time.now_ns as now
}

test_no_exceptions_file_is_fine if {
	count(governance.deny) == 0
	count(governance.warn) == 0
}

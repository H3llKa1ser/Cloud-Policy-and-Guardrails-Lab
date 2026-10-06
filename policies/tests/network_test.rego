package aws.network_test

import data.aws.network
import data.fixtures as f
import rego.v1

vpc_rule(from, to, proto, cidr) := f.rc("aws_vpc_security_group_ingress_rule", "r", {
	"from_port": from, "to_port": to, "ip_protocol": proto, "cidr_ipv4": cidr,
})

test_ssh_from_world_denied if {
	network.deny == {"[NET_001] aws_vpc_security_group_ingress_rule.r: port 22 open to 0.0.0.0/0"} with input as f.plan([vpc_rule(22, 22, "tcp", "0.0.0.0/0")])
}

test_ssh_from_internal_allowed if {
	count(network.deny) == 0 with input as f.plan([vpc_rule(22, 22, "tcp", "10.0.0.0/8")])
}

test_https_from_world_allowed if {
	count(network.deny) == 0 with input as f.plan([vpc_rule(443, 443, "tcp", "0.0.0.0/0")])
}

test_port_range_covering_rdp_denied if {
	"NET_001" in f.ids(network.deny) with input as f.plan([vpc_rule(3000, 4000, "tcp", "0.0.0.0/0")])
}

test_all_protocols_from_world_denied if {
	f.ids(network.deny) == {"NET_002"} with input as f.plan([vpc_rule(null, null, "-1", "0.0.0.0/0")])
}

test_inline_ipv6_ingress_denied if {
	sg := f.rc("aws_security_group", "web", {"ingress": [{
		"from_port": 3389, "to_port": 3389, "protocol": "tcp",
		"cidr_blocks": [], "ipv6_cidr_blocks": ["::/0"],
	}]})
	network.deny == {"[NET_001] aws_security_group.web: port 3389 open to ::/0"} with input as f.plan([sg])
}

test_legacy_rule_full_range_denied if {
	r := f.rc("aws_security_group_rule", "r", {
		"type": "ingress", "from_port": 0, "to_port": 65535, "protocol": "tcp",
		"cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": [],
	})
	f.ids(network.deny) == {"NET_002"} with input as f.plan([r])
}

test_legacy_egress_ignored if {
	r := f.rc("aws_security_group_rule", "r", {
		"type": "egress", "from_port": 0, "to_port": 0, "protocol": "-1",
		"cidr_blocks": ["0.0.0.0/0"],
	})
	count(network.deny) == 0 with input as f.plan([r])
}

test_default_sg_with_rules_denied if {
	sg := f.rc("aws_default_security_group", "default", {"ingress": [{"protocol": "-1"}], "egress": []})
	f.ids(network.deny) == {"NET_003"} with input as f.plan([sg])
}

test_default_sg_locked_down_allowed if {
	sg := f.rc("aws_default_security_group", "default", {"ingress": [], "egress": []})
	count(network.deny) == 0 with input as f.plan([sg])
}

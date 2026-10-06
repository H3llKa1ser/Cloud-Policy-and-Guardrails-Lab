# Network guardrails: nothing administrative is reachable from the internet.
#
# Control mappings follow the AWS Security Hub control reference.
package aws.network

import data.lib.exceptions
import data.lib.tf
import rego.v1

# Ports that must never be exposed to 0.0.0.0/0 or ::/0.
sensitive_ports := {
	22, # SSH
	23, # Telnet
	445, # SMB
	1433, # MSSQL
	1521, # Oracle
	2375, # Docker API (plaintext)
	3306, # MySQL
	3389, # RDP
	5432, # PostgreSQL
	5601, # Kibana
	5900, # VNC
	6379, # Redis
	9200, # Elasticsearch
	11211, # Memcached
	27017, # MongoDB
}

# ---------------------------------------------------------------------------
# Normalise the three ways AWS ingress can be expressed into one shape:
#   {address, cidrs, from, to, protocol}
# ---------------------------------------------------------------------------

# Inline ingress blocks on aws_security_group.
ingress contains rule if {
	some sg in tf.resources("aws_security_group")
	some block in tf.attr(sg, "ingress", [])
	rule := {
		"address": sg.address,
		"cidrs": {c | some c in array.concat(object.get(block, "cidr_blocks", []), object.get(block, "ipv6_cidr_blocks", []))},
		"from": block.from_port,
		"to": block.to_port,
		"protocol": block.protocol,
	}
}

# Legacy standalone aws_security_group_rule.
ingress contains rule if {
	some r in tf.resources("aws_security_group_rule")
	tf.attr(r, "type", "") == "ingress"
	rule := {
		"address": r.address,
		"cidrs": {c | some c in array.concat(tf.attr(r, "cidr_blocks", []), tf.attr(r, "ipv6_cidr_blocks", []))},
		"from": tf.attr(r, "from_port", 0),
		"to": tf.attr(r, "to_port", 65535),
		"protocol": tf.attr(r, "protocol", "-1"),
	}
}

# Current-style aws_vpc_security_group_ingress_rule.
ingress contains rule if {
	some r in tf.resources("aws_vpc_security_group_ingress_rule")
	rule := {
		"address": r.address,
		"cidrs": {c | some c in [tf.attr(r, "cidr_ipv4", ""), tf.attr(r, "cidr_ipv6", "")]; c != ""},
		"from": tf.attr(r, "from_port", 0),
		"to": tf.attr(r, "to_port", 65535),
		"protocol": tf.attr(r, "ip_protocol", "-1"),
	}
}

all_traffic(rule) if lower(sprintf("%v", [rule.protocol])) in {"-1", "all"}

all_traffic(rule) if {
	rule.from == 0
	rule.to == 65535
}

world_open(rule) := cidr if {
	some cidr in rule.cidrs
	cidr in tf.world_cidrs
}

# METADATA
# title: No sensitive port is reachable from the internet
# custom:
#   id: NET_001
#   level: deny
#   severity: high
#   mapping: aws-security-hub
#   controls:
#     aws_fsbp: [EC2.19, EC2.53, EC2.54]
#     cis_aws_v5: ["5.3", "5.4"]
#     nist_800_53_r5: [AC-4, CM-7, SC-7]
findings contains f if {
	some rule in ingress
	cidr := world_open(rule)
	not all_traffic(rule)
	some port in sensitive_ports
	rule.from <= port
	port <= rule.to
	f := tf.finding(rego.metadata.rule(), rule, sprintf("port %d open to %s", [port, cidr]))
}

# METADATA
# title: No security group allows all traffic from the internet
# custom:
#   id: NET_002
#   level: deny
#   severity: critical
#   mapping: aws-security-hub
#   controls:
#     aws_fsbp: [EC2.18, EC2.53, EC2.54]
#     cis_aws_v5: ["5.3", "5.4"]
#     nist_800_53_r5: [AC-4, CM-7, SC-7]
findings contains f if {
	some rule in ingress
	cidr := world_open(rule)
	all_traffic(rule)
	f := tf.finding(rego.metadata.rule(), rule, sprintf("all traffic open to %s", [cidr]))
}

# METADATA
# title: The default security group allows no traffic
# custom:
#   id: NET_003
#   level: deny
#   severity: high
#   mapping: aws-security-hub
#   controls:
#     aws_fsbp: [EC2.2]
#     cis_aws_v5: ["5.5"]
#     nist_800_53_r5: [AC-4, SC-7]
findings contains f if {
	some sg in tf.resources("aws_default_security_group")
	some direction in {"ingress", "egress"}
	count(tf.attr(sg, direction, [])) > 0
	f := tf.finding(rego.metadata.rule(), sg, sprintf("default security group must not define %s rules", [direction]))
}

deny contains tf.format(f) if {
	some f in findings
	f.level == "deny"
	not exceptions.exempt(f.id, f.address)
}

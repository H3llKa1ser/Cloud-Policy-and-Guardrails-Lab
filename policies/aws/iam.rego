# IAM guardrails: no admin-by-wildcard, no world-assumable roles,
# no long-lived human credentials.
package aws.iam

import data.lib.exceptions
import data.lib.tf
import rego.v1

policy_types := {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}

attachment_types := {"aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment", "aws_iam_group_policy_attachment", "aws_iam_policy_attachment"}

# Services where a wildcard on "*" is effectively privilege escalation.
sensitive_services := {"iam", "kms", "sts", "organizations", "account"}

admin_policy_arns := {
	"arn:aws:iam::aws:policy/AdministratorAccess",
	"arn:aws:iam::aws:policy/IAMFullAccess",
}

# --- helpers ---------------------------------------------------------------

as_set(x) := s if {
	is_array(x)
	s := {v | some v in x}
} else := {x}

# Parsed statements of a JSON policy attribute. Unknown (computed) policies
# are absent from the plan and are simply not evaluated.
statements(rc, attr_name) := stmts if {
	raw := tf.attr(rc, attr_name, "")
	is_string(raw)
	raw != ""
	doc := json.unmarshal(raw)
	stmts := as_set(doc.Statement)
}

allow_statements(rc, attr_name) := {s |
	some s in statements(rc, attr_name)
	s.Effect == "Allow"
}

actions(s) := as_set(object.get(s, "Action", []))

resources(s) := as_set(object.get(s, "Resource", []))

# --- rules -----------------------------------------------------------------

# METADATA
# title: No policy grants Action "*" on Resource "*"
# custom:
#   id: IAM_001
#   level: deny
#   severity: critical
#   mapping: aws-security-hub
#   controls:
#     aws_fsbp: [IAM.1]
#     nist_800_53_r5: [AC-2, AC-3, AC-5, AC-6]
findings contains f if {
	some rc in tf.resources_of(policy_types)
	some s in allow_statements(rc, "policy")
	some a in actions(s)
	a in {"*", "*:*"}
	"*" in resources(s)
	f := tf.finding(rego.metadata.rule(), rc, "policy grants Action \"*\" on Resource \"*\"")
}

# METADATA
# title: No service-wide wildcard on a sensitive service
# description: iam:*, kms:*, sts:*, organizations:* or account:* on Resource "*" is privilege escalation or key takeover.
# custom:
#   id: IAM_002
#   level: deny
#   severity: high
#   mapping: aws-security-hub
#   controls:
#     aws_fsbp: [IAM.21]
#     nist_800_53_r5: [AC-2, AC-3, AC-5, AC-6]
findings contains f if {
	some rc in tf.resources_of(policy_types)
	some s in allow_statements(rc, "policy")
	some a in actions(s)
	some svc in sensitive_services
	lower(a) == sprintf("%s:*", [svc])
	"*" in resources(s)
	f := tf.finding(rego.metadata.rule(), rc, sprintf("policy grants %q on Resource \"*\"", [a]))
}

# METADATA
# title: AWS-managed administrator policies are not attached
# custom:
#   id: IAM_003
#   level: deny
#   severity: critical
#   mapping: author
#   controls:
#     nist_800_53_r5: [AC-2, AC-6]
findings contains f if {
	some rc in tf.resources_of(attachment_types)
	arn := tf.attr(rc, "policy_arn", "")
	arn in admin_policy_arns
	f := tf.finding(rego.metadata.rule(), rc, sprintf("attaches %s", [arn]))
}

# METADATA
# title: No role is assumable by any AWS principal without a Condition
# custom:
#   id: IAM_004
#   level: deny
#   severity: critical
#   mapping: author
#   controls:
#     nist_800_53_r5: [AC-3, AC-6]
findings contains f if {
	some rc in tf.resources("aws_iam_role")
	some s in allow_statements(rc, "assume_role_policy")
	world_principal(object.get(s, "Principal", {}))
	not s.Condition
	f := tf.finding(rego.metadata.rule(), rc, "assume_role_policy trusts any principal without a Condition")
}

world_principal(p) if p == "*"

world_principal(p) if "*" in as_set(object.get(p, "AWS", []))

# METADATA
# title: No long-lived IAM access keys
# custom:
#   id: IAM_101
#   level: warn
#   severity: medium
#   mapping: author
#   controls:
#     nist_800_53_r5: [AC-2, IA-5]
findings contains f if {
	some rc in tf.resources("aws_iam_access_key")
	f := tf.finding(rego.metadata.rule(), rc, "creates a long-lived access key; prefer roles or IAM Identity Center")
}

# METADATA
# title: Permissions are not attached directly to IAM users
# custom:
#   id: IAM_102
#   level: warn
#   severity: low
#   mapping: aws-security-hub
#   controls:
#     aws_fsbp: [IAM.2]
#     cis_aws_v5: ["1.14"]
#     nist_800_53_r5: [AC-2, AC-3, AC-6]
findings contains f if {
	some rc in tf.resources_of({"aws_iam_user_policy", "aws_iam_user_policy_attachment"})
	f := tf.finding(rego.metadata.rule(), rc, "attach permissions to groups or roles, not users")
}

# METADATA
# title: Allow statements do not use NotAction
# custom:
#   id: IAM_103
#   level: warn
#   severity: medium
#   mapping: author
#   controls:
#     nist_800_53_r5: [AC-6]
findings contains f if {
	some rc in tf.resources_of(policy_types)
	some s in allow_statements(rc, "policy")
	s.NotAction
	f := tf.finding(rego.metadata.rule(), rc, "Allow statement uses NotAction")
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

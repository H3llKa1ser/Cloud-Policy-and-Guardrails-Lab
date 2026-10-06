package aws.iam_test

import data.aws.iam
import data.fixtures as f
import rego.v1

policy(stmts) := f.rc("aws_iam_policy", "p", {"policy": json.marshal({"Version": "2012-10-17", "Statement": stmts})})

test_scoped_policy_passes if {
	p := policy([{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::bucket/*"}])
	count(iam.deny) == 0 with input as f.plan([p])
	count(iam.warn) == 0 with input as f.plan([p])
}

test_star_star_denied if {
	p := policy({"Effect": "Allow", "Action": "*", "Resource": "*"})
	f.ids(iam.deny) == {"IAM_001"} with input as f.plan([p])
}

test_deny_star_star_is_fine if {
	p := policy([{"Effect": "Deny", "Action": "*", "Resource": "*"}])
	count(iam.deny) == 0 with input as f.plan([p])
}

test_iam_wildcard_denied_case_insensitive if {
	p := policy([{"Effect": "Allow", "Action": ["s3:GetObject", "IAM:*"], "Resource": ["*"]}])
	f.ids(iam.deny) == {"IAM_002"} with input as f.plan([p])
}

test_inline_role_policy_checked if {
	rp := f.rc("aws_iam_role_policy", "rp", {"policy": json.marshal({"Statement": [{"Effect": "Allow", "Action": "kms:*", "Resource": "*"}]})})
	f.ids(iam.deny) == {"IAM_002"} with input as f.plan([rp])
}

test_unknown_policy_skipped if {
	p := f.rc("aws_iam_policy", "p", {})
	count(iam.deny) == 0 with input as f.plan([p])
}

test_admin_attachment_denied if {
	a := f.rc("aws_iam_role_policy_attachment", "a", {"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"})
	f.ids(iam.deny) == {"IAM_003"} with input as f.plan([a])
}

test_world_trust_policy_denied if {
	r := f.rc("aws_iam_role", "r", {"assume_role_policy": json.marshal({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]})})
	f.ids(iam.deny) == {"IAM_004"} with input as f.plan([r])
}

test_world_trust_with_condition_allowed if {
	r := f.rc("aws_iam_role", "r", {"assume_role_policy": json.marshal({"Statement": [{
		"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole",
		"Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}},
	}]})})
	count(iam.deny) == 0 with input as f.plan([r])
}

test_service_trust_allowed if {
	r := f.rc("aws_iam_role", "r", {"assume_role_policy": json.marshal({"Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]})})
	count(iam.deny) == 0 with input as f.plan([r])
}

test_advisories if {
	p := f.plan([
		f.rc("aws_iam_access_key", "k", {}),
		f.rc("aws_iam_user_policy_attachment", "u", {"policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}),
		policy([{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]),
	])
	f.ids(iam.warn) == {"IAM_101", "IAM_102", "IAM_103"} with input as p
}

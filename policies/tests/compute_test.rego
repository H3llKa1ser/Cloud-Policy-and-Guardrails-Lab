package aws.compute_test

import data.aws.compute
import data.fixtures as f
import rego.v1

good_instance := {
	"metadata_options": [{"http_tokens": "required"}],
	"root_block_device": [{"encrypted": true}],
}

test_hardened_instance_passes if {
	count(compute.deny) == 0 with input as f.plan([f.rc("aws_instance", "app", good_instance)])
}

test_imdsv1_denied if {
	i := object.union(good_instance, {"metadata_options": [{"http_tokens": "optional"}]})
	f.ids(compute.deny) == {"CMP_001"} with input as f.plan([f.rc("aws_instance", "app", i)])
}

test_unset_metadata_options_denied if {
	f.ids(compute.deny) == {"CMP_001", "CMP_002"} with input as f.plan([f.rc("aws_instance", "app", {})])
}

test_launch_template_imds_checked if {
	f.ids(compute.deny) == {"CMP_001"} with input as f.plan([f.rc("aws_launch_template", "lt", {})])
}

test_ebs_default_encryption_satisfies_root_volume if {
	p := f.plan([
		f.rc("aws_ebs_encryption_by_default", "this", {"enabled": true}),
		f.rc("aws_instance", "app", {"metadata_options": [{"http_tokens": "required"}]}),
		f.rc("aws_ebs_volume", "data", {}),
	])
	count(compute.deny) == 0 with input as p
}

test_unencrypted_volume_denied if {
	f.ids(compute.deny) == {"CMP_003"} with input as f.plan([f.rc("aws_ebs_volume", "data", {"encrypted": false})])
}

test_public_ip_warned if {
	i := object.union(good_instance, {"associate_public_ip_address": true})
	f.ids(compute.warn) == {"CMP_101"} with input as f.plan([f.rc("aws_instance", "app", i)])
}

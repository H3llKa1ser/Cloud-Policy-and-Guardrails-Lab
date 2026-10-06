package aws.logging_test

import data.aws.logging
import data.fixtures as f
import rego.v1

good_trail := {
	"is_multi_region_trail": true,
	"enable_log_file_validation": true,
	"include_global_service_events": true,
	"kms_key_id": "arn:aws:kms:eu-west-1:123456789012:key/abc",
}

test_good_trail_passes if {
	count(logging.deny) == 0 with input as f.plan([f.rc("aws_cloudtrail", "t", good_trail)])
}

test_kms_key_known_after_apply_passes if {
	t := f.with_unknown(f.rc("aws_cloudtrail", "t", object.remove(good_trail, ["kms_key_id"])), {"kms_key_id": true})
	count(logging.deny) == 0 with input as f.plan([t])
}

test_weak_trail_denied if {
	t := f.rc("aws_cloudtrail", "t", {"include_global_service_events": false})
	f.ids(logging.deny) == {"LOG_001", "LOG_002", "LOG_003", "LOG_004"} with input as f.plan([t])
}

test_log_group_advisories if {
	f.ids(logging.warn) == {"LOG_101", "LOG_102"} with input as f.plan([f.rc("aws_cloudwatch_log_group", "g", {"retention_in_days": 0})])
}

test_log_group_with_retention_and_kms_passes if {
	g := f.rc("aws_cloudwatch_log_group", "g", {"retention_in_days": 365, "kms_key_id": "arn:aws:kms:x"})
	count(logging.warn) == 0 with input as f.plan([g])
}

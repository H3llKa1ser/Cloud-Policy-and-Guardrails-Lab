package aws.s3_test

import data.aws.s3
import data.fixtures as f
import rego.v1

pab_all_true := {
	"block_public_acls": true, "block_public_policy": true,
	"ignore_public_acls": true, "restrict_public_buckets": true,
}

bucket := f.rc("aws_s3_bucket", "logs", {"bucket": "logs"})

compliant_root := f.plan_cfg(
	[
		bucket,
		f.rc("aws_s3_bucket_public_access_block", "logs", pab_all_true),
		f.rc("aws_s3_bucket_server_side_encryption_configuration", "logs", {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]}),
		f.rc("aws_s3_bucket_versioning", "logs", {}),
	],
	{"resources": [
		f.cfg_ref("aws_s3_bucket_public_access_block", "logs", "bucket", "aws_s3_bucket", "logs"),
		f.cfg_ref("aws_s3_bucket_server_side_encryption_configuration", "logs", "bucket", "aws_s3_bucket", "logs"),
		f.cfg_ref("aws_s3_bucket_versioning", "logs", "bucket", "aws_s3_bucket", "logs"),
	]},
)

test_compliant_bucket_passes if {
	count(s3.deny) == 0 with input as compliant_root
	count(s3.warn) == 0 with input as compliant_root
}

test_bucket_without_companions_denied if {
	ids := f.ids(s3.deny) with input as f.plan([bucket])
	ids == {"S3_001", "S3_003"}
}

test_bucket_without_versioning_warned if {
	"S3_102" in f.ids(s3.warn) with input as f.plan([bucket])
}

test_pab_companion_must_reference_same_bucket if {
	other := f.rc("aws_s3_bucket", "other", {})
	p := f.plan_cfg(
		[bucket, other, f.rc("aws_s3_bucket_public_access_block", "x", pab_all_true)],
		{"resources": [f.cfg_ref("aws_s3_bucket_public_access_block", "x", "bucket", "aws_s3_bucket", "other")]},
	)
	denies := s3.deny with input as p
	"[S3_001] aws_s3_bucket.logs: bucket has no aws_s3_bucket_public_access_block" in denies
	not "[S3_001] aws_s3_bucket.other: bucket has no aws_s3_bucket_public_access_block" in denies
}

test_companion_resolved_inside_nested_module if {
	mod := `module.app["eu"].module.data[0]`
	p := f.plan_cfg(
		[
			f.rc_in(mod, "aws_s3_bucket", "this", {}),
			f.rc_in(mod, "aws_s3_bucket_public_access_block", "this", pab_all_true),
		],
		{"module_calls": {"app": {"module": {"module_calls": {"data": {"module": {"resources": [
			f.cfg_ref("aws_s3_bucket_public_access_block", "this", "bucket", "aws_s3_bucket", "this"),
		]}}}}}}},
	)
	not "S3_001" in f.ids(s3.deny) with input as p
}

test_companion_in_other_module_does_not_count if {
	p := f.plan_cfg(
		[
			f.rc_in("module.a", "aws_s3_bucket", "this", {}),
			f.rc_in("module.b", "aws_s3_bucket_public_access_block", "this", pab_all_true),
		],
		{"module_calls": {"b": {"module": {"resources": [
			f.cfg_ref("aws_s3_bucket_public_access_block", "this", "bucket", "aws_s3_bucket", "this"),
		]}}}},
	)
	"S3_001" in f.ids(s3.deny) with input as p
}

test_pab_flag_false_denied if {
	p := f.plan([f.rc("aws_s3_bucket_public_access_block", "x", object.union(pab_all_true, {"restrict_public_buckets": false}))])
	s3.deny == {"[S3_002] aws_s3_bucket_public_access_block.x: public access block must set restrict_public_buckets = true"} with input as p
}

test_public_acl_denied if {
	"S3_004" in f.ids(s3.deny) with input as f.plan([f.rc("aws_s3_bucket_acl", "x", {"acl": "public-read"})])
}

test_private_acl_allowed if {
	count(s3.deny) == 0 with input as f.plan([f.rc("aws_s3_bucket_acl", "x", {"acl": "private"})])
}

test_sse_s3_warned if {
	p := f.plan([f.rc("aws_s3_bucket_server_side_encryption_configuration", "x", {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]})])
	"S3_101" in f.ids(s3.warn) with input as p
}

test_deleted_bucket_not_judged if {
	count(s3.deny) == 0 with input as f.plan([f.with_actions(bucket, ["delete"])])
}

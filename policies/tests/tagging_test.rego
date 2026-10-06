package aws.tagging_test

import data.aws.tagging
import data.fixtures as f
import rego.v1

good_tags := {"Owner": "secops", "Environment": "lab", "DataClassification": "internal"}

test_fully_tagged_passes if {
	p := f.plan([f.rc("aws_s3_bucket", "b", {"tags": {}, "tags_all": good_tags})])
	count(tagging.deny) == 0 with input as p
	count(tagging.warn) == 0 with input as p
}

test_missing_tags_warned if {
	p := f.plan([f.rc("aws_s3_bucket", "b", {"tags": {"Owner": "secops"}})])
	tagging.warn == {"[TAG_101] aws_s3_bucket.b: missing required tag(s): DataClassification, Environment"} with input as p
}

# Regression: real plans mark a *known* map as {} in after_unknown.
test_known_tags_all_marked_empty_object_is_judged if {
	p := f.plan([f.with_unknown(f.rc("aws_s3_bucket", "b", {"tags_all": {"Owner": "secops"}}), {"tags_all": {}})])
	f.ids(tagging.warn) == {"TAG_101"} with input as p
}

# Unknown tags_all and no way to resolve provider default_tags: skip.
test_unresolvable_tags_not_judged if {
	p := f.plan([f.with_unknown(f.rc("aws_s3_bucket", "b", {"tags": {}}), {"tags_all": true})])
	count(tagging.warn) == 0 with input as p
}

provider_cfg_resource := {"address": "aws_s3_bucket.b", "provider_config_key": "aws.untagged", "expressions": {}}

# Unknown tags_all because the provider has no default_tags: judge on resource tags.
test_untagged_provider_judged_from_config if {
	p := f.plan_cfg(
		[f.with_unknown(f.rc("aws_s3_bucket", "b", {"tags": {"Owner": "secops"}}), {"tags_all": true})],
		{"resources": [provider_cfg_resource]},
	)
	q := object.union(p, {"configuration": object.union(p.configuration, {"provider_config": {"aws.untagged": {"name": "aws", "alias": "untagged", "expressions": {"region": {"constant_value": "eu-west-1"}}}}})})
	tagging.warn == {"[TAG_101] aws_s3_bucket.b: missing required tag(s): DataClassification, Environment"} with input as q
}

# Unknown tags_all but statically known default_tags: merge them.
test_constant_default_tags_merged if {
	p := f.plan_cfg(
		[f.with_unknown(f.rc("aws_s3_bucket", "b", {"tags": {"DataClassification": "internal"}}), {"tags_all": true})],
		{"resources": [provider_cfg_resource]},
	)
	pc := {"aws.untagged": {"expressions": {"default_tags": [{"tags": {"constant_value": {"Owner": "secops", "Environment": "lab"}}}]}}}
	q := object.union(p, {"configuration": object.union(p.configuration, {"provider_config": pc})})
	count(tagging.warn) == 0 with input as q
}

# Resource tags themselves unknown (e.g. built from another resource's output): skip.
test_unknown_resource_tags_not_judged if {
	p := f.plan([f.with_unknown(f.rc("aws_s3_bucket", "b", {}), {"tags": true, "tags_all": true})])
	count(tagging.warn) == 0 with input as p
}

test_untaggable_resource_ignored if {
	count(tagging.warn) == 0 with input as f.plan([f.rc("aws_s3_bucket_public_access_block", "b", {})])
}

test_bad_values_denied if {
	t := object.union(good_tags, {"DataClassification": "secret", "Environment": "production"})
	f.ids(tagging.deny) == {"TAG_001", "TAG_002"} with input as f.plan([f.rc("aws_s3_bucket", "b", {"tags_all": t})])
}

# default_tags built from a variable cannot be resolved at plan time: skip.
test_dynamic_default_tags_not_judged if {
	p := f.plan_cfg(
		[f.with_unknown(f.rc("aws_s3_bucket", "b", {"tags": {}}), {"tags_all": true})],
		{"resources": [provider_cfg_resource]},
	)
	pc := {"aws.untagged": {"expressions": {"default_tags": [{"tags": {"references": ["var.tags"]}}]}}}
	q := object.union(p, {"configuration": object.union(p.configuration, {"provider_config": pc})})
	count(tagging.warn) == 0 with input as q
}

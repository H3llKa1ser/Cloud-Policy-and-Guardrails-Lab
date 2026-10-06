# Logging guardrails: audit trails are complete, tamper-evident, encrypted,
# and log groups have a retention decision.
package aws.logging

import data.lib.exceptions
import data.lib.tf
import rego.v1

# METADATA
# title: CloudTrail trails are multi-region
# custom:
#   id: LOG_001
#   level: deny
#   severity: high
#   mapping: aws-security-hub
#   controls:
#     aws_fsbp: [CloudTrail.1]
#     cis_aws_v5: ["3.1"]
#     nist_800_53_r5: [AU-2, AU-3, AU-12, CA-7]
findings contains f if {
	some rc in tf.resources("aws_cloudtrail")
	tf.attr(rc, "is_multi_region_trail", false) != true
	f := tf.finding(rego.metadata.rule(), rc, "is_multi_region_trail must be true")
}

# METADATA
# title: CloudTrail log file validation is enabled
# custom:
#   id: LOG_002
#   level: deny
#   severity: medium
#   mapping: aws-security-hub
#   controls:
#     aws_fsbp: [CloudTrail.4]
#     cis_aws_v5: ["3.2"]
#     nist_800_53_r5: [AU-9, SI-4, SI-7]
findings contains f if {
	some rc in tf.resources("aws_cloudtrail")
	tf.attr(rc, "enable_log_file_validation", false) != true
	f := tf.finding(rego.metadata.rule(), rc, "enable_log_file_validation must be true")
}

# METADATA
# title: CloudTrail logs are encrypted with a customer-managed KMS key
# custom:
#   id: LOG_003
#   level: deny
#   severity: medium
#   mapping: aws-security-hub
#   controls:
#     aws_fsbp: [CloudTrail.2]
#     cis_aws_v5: ["3.5"]
#     nist_800_53_r5: [AU-9, SC-13, SC-28]
findings contains f if {
	some rc in tf.resources("aws_cloudtrail")
	not tf.is_set(rc, "kms_key_id")
	f := tf.finding(rego.metadata.rule(), rc, "kms_key_id must be set")
}

# METADATA
# title: CloudTrail captures global service events (IAM, STS)
# custom:
#   id: LOG_004
#   level: deny
#   severity: high
#   mapping: aws-security-hub
#   controls:
#     aws_fsbp: [CloudTrail.1]
#     cis_aws_v5: ["3.1"]
#     nist_800_53_r5: [AU-2, AU-12]
findings contains f if {
	some rc in tf.resources("aws_cloudtrail")
	tf.attr(rc, "include_global_service_events", true) != true
	f := tf.finding(rego.metadata.rule(), rc, "include_global_service_events must be true")
}

# METADATA
# title: CloudWatch log groups have a retention period
# custom:
#   id: LOG_101
#   level: warn
#   severity: medium
#   mapping: aws-security-hub
#   controls:
#     aws_fsbp: [CloudWatch.16]
#     nist_800_53_r5: [AU-11, SI-12]
findings contains f if {
	some rc in tf.resources("aws_cloudwatch_log_group")
	tf.attr(rc, "retention_in_days", 0) == 0
	f := tf.finding(rego.metadata.rule(), rc, "retention_in_days is not set (logs kept forever)")
}

# METADATA
# title: CloudWatch log groups are encrypted with a customer-managed KMS key
# custom:
#   id: LOG_102
#   level: warn
#   severity: low
#   mapping: author
#   controls:
#     nist_800_53_r5: [AU-9, SC-28]
findings contains f if {
	some rc in tf.resources("aws_cloudwatch_log_group")
	not tf.is_set(rc, "kms_key_id")
	f := tf.finding(rego.metadata.rule(), rc, "kms_key_id is not set")
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

# S3 guardrails: no public buckets, encryption at rest, recoverability.
#
# Control mappings follow the AWS Security Hub control reference
# (FSBP control -> CIS AWS Foundations v5.0.0 / NIST SP 800-53 Rev. 5).
package aws.s3

import data.lib.exceptions
import data.lib.tf
import rego.v1

pab_flags := {"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"}

public_acls := {"public-read", "public-read-write", "authenticated-read"}

# METADATA
# title: Every bucket has a public access block
# custom:
#   id: S3_001
#   level: deny
#   severity: high
#   mapping: aws-security-hub
#   controls:
#     aws_fsbp: [S3.8]
#     cis_aws_v5: ["2.1.4"]
#     nist_800_53_r5: [AC-3, AC-4, AC-6, AC-21, SC-7]
findings contains f if {
	some b in tf.resources("aws_s3_bucket")
	not tf.has_companion(b, "aws_s3_bucket_public_access_block", "bucket")
	f := tf.finding(rego.metadata.rule(), b, "bucket has no aws_s3_bucket_public_access_block")
}

# METADATA
# title: All four public access block settings are enabled
# custom:
#   id: S3_002
#   level: deny
#   severity: high
#   mapping: aws-security-hub
#   controls:
#     aws_fsbp: [S3.8]
#     cis_aws_v5: ["2.1.4"]
#     nist_800_53_r5: [AC-3, AC-4, AC-6, AC-21, SC-7]
findings contains f if {
	some pab in tf.resources("aws_s3_bucket_public_access_block")
	some flag in pab_flags
	tf.attr(pab, flag, false) != true
	f := tf.finding(rego.metadata.rule(), pab, sprintf("public access block must set %s = true", [flag]))
}

# METADATA
# title: Every bucket has default server-side encryption configured
# custom:
#   id: S3_003
#   level: deny
#   severity: medium
#   mapping: author
#   controls:
#     nist_800_53_r5: [SC-13, SC-28]
findings contains f if {
	some b in tf.resources("aws_s3_bucket")
	not tf.has_companion(b, "aws_s3_bucket_server_side_encryption_configuration", "bucket")
	f := tf.finding(rego.metadata.rule(), b, "bucket has no aws_s3_bucket_server_side_encryption_configuration")
}

# METADATA
# title: No canned ACL grants public access
# custom:
#   id: S3_004
#   level: deny
#   severity: critical
#   mapping: aws-security-hub
#   controls:
#     aws_fsbp: [S3.2, S3.3, S3.12]
#     nist_800_53_r5: [AC-3, AC-4, AC-6, AC-21, SC-7]
findings contains f if {
	some acl in tf.resources("aws_s3_bucket_acl")
	tf.attr(acl, "acl", "") in public_acls
	f := tf.finding(rego.metadata.rule(), acl, sprintf("canned ACL %q grants public access", [tf.attr(acl, "acl", "")]))
}

# METADATA
# title: Buckets are encrypted with AWS KMS rather than SSE-S3
# custom:
#   id: S3_101
#   level: warn
#   severity: medium
#   mapping: aws-security-hub
#   controls:
#     aws_fsbp: [S3.17]
#     nist_800_53_r5: [AU-9, SC-12, SC-13, SC-28]
findings contains f if {
	some sse in tf.resources("aws_s3_bucket_server_side_encryption_configuration")
	some rule in tf.attr(sse, "rule", [])
	some def in rule.apply_server_side_encryption_by_default
	algo := def.sse_algorithm
	not startswith(algo, "aws:kms")
	f := tf.finding(rego.metadata.rule(), sse, sprintf("uses %q; prefer aws:kms with a customer-managed key", [algo]))
}

# METADATA
# title: Every bucket has versioning configured
# custom:
#   id: S3_102
#   level: warn
#   severity: low
#   mapping: aws-security-hub
#   controls:
#     aws_fsbp: [S3.14]
#     nist_800_53_r5: [AU-9, CP-6, CP-9, CP-10, SI-12]
findings contains f if {
	some b in tf.resources("aws_s3_bucket")
	not tf.has_companion(b, "aws_s3_bucket_versioning", "bucket")
	f := tf.finding(rego.metadata.rule(), b, "bucket has no aws_s3_bucket_versioning")
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

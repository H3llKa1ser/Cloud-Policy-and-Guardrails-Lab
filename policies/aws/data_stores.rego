# Data store guardrails: databases are private and encrypted, keys rotate.
package aws.data_stores

import data.lib.exceptions
import data.lib.tf
import rego.v1

db_types := {"aws_db_instance", "aws_rds_cluster"}

# METADATA
# title: Database storage is encrypted at rest
# custom:
#   id: DATA_001
#   level: deny
#   severity: high
#   mapping: aws-security-hub
#   controls:
#     aws_fsbp: [RDS.3, RDS.27]
#     cis_aws_v5: ["2.2.1"]
#     nist_800_53_r5: [SC-13, SC-28]
findings contains f if {
	some rc in tf.resources_of(db_types)
	tf.attr(rc, "storage_encrypted", false) != true
	f := tf.finding(rego.metadata.rule(), rc, "storage_encrypted must be true")
}

# METADATA
# title: Database instances are not publicly accessible
# custom:
#   id: DATA_002
#   level: deny
#   severity: critical
#   mapping: aws-security-hub
#   controls:
#     aws_fsbp: [RDS.2]
#     cis_aws_v5: ["2.2.3"]
#     nist_800_53_r5: [AC-4, SC-7]
findings contains f if {
	some rc in tf.resources("aws_db_instance")
	tf.attr(rc, "publicly_accessible", false) == true
	f := tf.finding(rego.metadata.rule(), rc, "publicly_accessible must be false")
}

# METADATA
# title: Symmetric customer-managed KMS keys rotate
# custom:
#   id: DATA_003
#   level: deny
#   severity: medium
#   mapping: aws-security-hub
#   controls:
#     aws_fsbp: [KMS.4]
#     cis_aws_v5: ["3.6"]
#     nist_800_53_r5: [SC-12, SC-28]
findings contains f if {
	some rc in tf.resources("aws_kms_key")
	tf.attr(rc, "customer_master_key_spec", "SYMMETRIC_DEFAULT") == "SYMMETRIC_DEFAULT"
	tf.attr(rc, "enable_key_rotation", false) != true
	f := tf.finding(rego.metadata.rule(), rc, "enable_key_rotation must be true")
}

deny contains tf.format(f) if {
	some f in findings
	f.level == "deny"
	not exceptions.exempt(f.id, f.address)
}

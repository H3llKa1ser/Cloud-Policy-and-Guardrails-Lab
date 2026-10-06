# Compute guardrails: IMDSv2, encrypted disks, no accidental public IPs.
package aws.compute

import data.lib.exceptions
import data.lib.tf
import rego.v1

launch_types := {"aws_instance", "aws_launch_template"}

# Account-wide EBS default encryption satisfies CMP_002 for every instance.
ebs_default_encryption if {
	some r in tf.managed
	r.type == "aws_ebs_encryption_by_default"
	tf.attr(r, "enabled", false) == true
}

# METADATA
# title: Instances and launch templates require IMDSv2
# custom:
#   id: CMP_001
#   level: deny
#   severity: high
#   mapping: aws-security-hub
#   controls:
#     aws_fsbp: [EC2.8, EC2.170]
#     cis_aws_v5: ["5.7"]
#     nist_800_53_r5: [AC-3, AC-6]
findings contains f if {
	some rc in tf.resources_of(launch_types)
	object.get(tf.first_block(rc, "metadata_options"), "http_tokens", "unset") != "required"
	f := tf.finding(rego.metadata.rule(), rc, "metadata_options.http_tokens must be \"required\" (IMDSv2)")
}

# METADATA
# title: Instance root volumes are encrypted
# custom:
#   id: CMP_002
#   level: deny
#   severity: medium
#   mapping: aws-security-hub
#   controls:
#     aws_fsbp: [EC2.3]
#     nist_800_53_r5: [SC-13, SC-28]
findings contains f if {
	not ebs_default_encryption
	some rc in tf.resources("aws_instance")
	object.get(tf.first_block(rc, "root_block_device"), "encrypted", false) != true
	f := tf.finding(rego.metadata.rule(), rc, "root_block_device.encrypted must be true (or enable aws_ebs_encryption_by_default)")
}

# METADATA
# title: EBS volumes are encrypted
# custom:
#   id: CMP_003
#   level: deny
#   severity: medium
#   mapping: aws-security-hub
#   controls:
#     aws_fsbp: [EC2.3]
#     nist_800_53_r5: [SC-13, SC-28]
findings contains f if {
	not ebs_default_encryption
	some rc in tf.resources("aws_ebs_volume")
	tf.attr(rc, "encrypted", false) != true
	f := tf.finding(rego.metadata.rule(), rc, "EBS volume must set encrypted = true")
}

# METADATA
# title: Instances do not request a public IPv4 address
# custom:
#   id: CMP_101
#   level: warn
#   severity: medium
#   mapping: aws-security-hub
#   controls:
#     aws_fsbp: [EC2.9]
#     nist_800_53_r5: [AC-3, AC-4, AC-6, AC-21, SC-7]
findings contains f if {
	some rc in tf.resources("aws_instance")
	tf.attr(rc, "associate_public_ip_address", false) == true
	f := tf.finding(rego.metadata.rule(), rc, "instance requests a public IP address")
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

package aws.data_stores_test

import data.aws.data_stores
import data.fixtures as f
import rego.v1

test_private_encrypted_db_passes if {
	db := f.rc("aws_db_instance", "db", {"storage_encrypted": true, "publicly_accessible": false})
	count(data_stores.deny) == 0 with input as f.plan([db])
}

test_public_unencrypted_db_denied if {
	db := f.rc("aws_db_instance", "db", {"storage_encrypted": false, "publicly_accessible": true})
	f.ids(data_stores.deny) == {"DATA_001", "DATA_002"} with input as f.plan([db])
}

test_aurora_cluster_encryption_checked if {
	f.ids(data_stores.deny) == {"DATA_001"} with input as f.plan([f.rc("aws_rds_cluster", "c", {})])
}

test_kms_without_rotation_denied if {
	f.ids(data_stores.deny) == {"DATA_003"} with input as f.plan([f.rc("aws_kms_key", "k", {"enable_key_rotation": false})])
}

test_asymmetric_kms_key_not_required_to_rotate if {
	k := f.rc("aws_kms_key", "k", {"customer_master_key_spec": "RSA_2048", "enable_key_rotation": false})
	count(data_stores.deny) == 0 with input as f.plan([k])
}

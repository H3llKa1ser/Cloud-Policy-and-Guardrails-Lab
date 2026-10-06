# Native `terraform test` with a mocked provider: runs offline, in seconds,
# and proves the module's secure defaults hold without touching AWS.

mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

variables {
  name = "guardrails-lab-test-bucket"
}

run "blocks_all_public_access" {
  command = plan

  assert {
    condition = alltrue([
      aws_s3_bucket_public_access_block.this.block_public_acls,
      aws_s3_bucket_public_access_block.this.block_public_policy,
      aws_s3_bucket_public_access_block.this.ignore_public_acls,
      aws_s3_bucket_public_access_block.this.restrict_public_buckets,
    ])
    error_message = "All four public access block flags must be true."
  }

  assert {
    condition     = one(aws_s3_bucket_ownership_controls.this.rule).object_ownership == "BucketOwnerEnforced"
    error_message = "ACLs must be disabled via BucketOwnerEnforced."
  }
}

run "encrypts_with_rotating_kms_key_by_default" {
  command = plan

  assert {
    condition     = length(aws_kms_key.this) == 1 && aws_kms_key.this[0].enable_key_rotation
    error_message = "A dedicated rotating KMS key should be created when none is supplied."
  }

  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.this.rule).apply_server_side_encryption_by_default).sse_algorithm == "aws:kms"
    error_message = "Default encryption must be aws:kms."
  }
}

run "uses_supplied_key_without_creating_one" {
  command = plan

  variables {
    create_kms_key = false
    kms_key_arn    = "arn:aws:kms:eu-west-1:123456789012:key/11111111-2222-3333-4444-555555555555"
  }

  assert {
    condition     = length(aws_kms_key.this) == 0
    error_message = "No key should be created when kms_key_arn is supplied."
  }

  assert {
    condition     = output.kms_key_arn == var.kms_key_arn
    error_message = "The supplied key must be used for encryption."
  }
}

run "rejects_missing_key_when_not_creating_one" {
  command = plan

  variables {
    create_kms_key = false
  }

  expect_failures = [var.kms_key_arn]
}

run "versioning_enabled" {
  command = plan

  assert {
    condition     = one(aws_s3_bucket_versioning.this.versioning_configuration).status == "Enabled"
    error_message = "Versioning must be enabled."
  }
}

run "rejects_invalid_bucket_name" {
  command = plan

  variables {
    name = "Not_A_Valid_Bucket"
  }

  expect_failures = [var.name]
}

run "rejects_too_short_version_retention" {
  command = plan

  variables {
    noncurrent_version_retention_days = 1
  }

  expect_failures = [var.noncurrent_version_retention_days]
}

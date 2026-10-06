mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }

  mock_resource "aws_kms_key" {
    defaults = {
      arn = "arn:aws:kms:eu-west-1:123456789012:key/00000000-0000-0000-0000-000000000000"
    }
  }

  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:eu-west-1:123456789012:log-group:/aws/cloudtrail/organisation-audit"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::123456789012:role/organisation-audit-to-cloudwatch"
    }
  }

  mock_resource "aws_s3_bucket" {
    defaults = {
      arn = "arn:aws:s3:::guardrails-lab-audit-logs"
    }
  }
}

variables {
  bucket_name = "guardrails-lab-audit-logs"
  account_id  = "123456789012"
  region      = "eu-west-1"
}

run "trail_meets_logging_guardrails" {
  command = apply

  assert {
    condition = alltrue([
      aws_cloudtrail.this.is_multi_region_trail,
      aws_cloudtrail.this.include_global_service_events,
      aws_cloudtrail.this.enable_log_file_validation,
    ])
    error_message = "Trail must be multi-region, include global events and validate log files."
  }

  assert {
    condition     = aws_cloudtrail.this.kms_key_id == aws_kms_key.this.arn
    error_message = "Trail must be encrypted with the module's KMS key."
  }

  assert {
    condition     = aws_kms_key.this.enable_key_rotation
    error_message = "KMS key must rotate."
  }

  assert {
    condition     = aws_cloudwatch_log_group.this.retention_in_days == 365
    error_message = "Default log retention should be one year."
  }
}

run "rejects_bad_account_id" {
  command = plan

  variables {
    account_id = "12345"
  }

  expect_failures = [var.account_id]
}

run "rejects_short_retention" {
  command = plan

  variables {
    log_retention_days = 30
  }

  expect_failures = [var.log_retention_days]
}

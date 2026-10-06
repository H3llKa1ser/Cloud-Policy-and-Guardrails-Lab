# A bucket that is private, encrypted, versioned and TLS-only by
# construction. Every control here maps to a rule in policies/aws/s3.rego,
# so consuming this module is the easy way to pass the guardrails.

locals {
  create_key  = var.create_kms_key
  kms_key_arn = local.create_key ? aws_kms_key.this[0].arn : var.kms_key_arn
}

resource "aws_kms_key" "this" {
  #checkov:skip=CKV2_AWS_64:Uses the AWS default key policy (account root) so the module plans offline; pass create_kms_key = false with a key carrying a custom policy for tighter control.
  count = local.create_key ? 1 : 0

  description             = "Default encryption for s3://${var.name}"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = var.tags
}

resource "aws_kms_alias" "this" {
  count = local.create_key ? 1 : 0

  name          = "alias/s3/${var.name}"
  target_key_id = aws_kms_key.this[0].key_id
}

resource "aws_s3_bucket" "this" {
  #checkov:skip=CKV_AWS_144:Cross-region replication is a resilience/cost decision per data set, not a baseline control.
  #checkov:skip=CKV2_AWS_62:Event notifications are workload-specific; CloudTrail data events cover audit needs.
  bucket        = var.name
  force_destroy = var.force_destroy
  tags          = var.tags
}

# ACLs disabled: access is governed only by IAM and the bucket policy.
resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.this.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = local.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    id     = "expire-noncurrent-and-abort-mpu"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_version_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

resource "aws_s3_bucket_logging" "this" {
  count = var.access_log_bucket == null ? 0 : 1

  bucket        = aws_s3_bucket.this.id
  target_bucket = var.access_log_bucket
  target_prefix = "${var.name}/"
}

data "aws_iam_policy_document" "this" {
  source_policy_documents = var.additional_policy_json == null ? [] : [var.additional_policy_json]

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.this.arn,
      "${aws_s3_bucket.this.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid     = "DenyOutdatedTLS"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.this.arn,
      "${aws_s3_bucket.this.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "NumericLessThan"
      variable = "s3:TlsVersion"
      values   = ["1.2"]
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = data.aws_iam_policy_document.this.json

  # Applying a policy before the public access block exists can briefly
  # leave a window where a public policy would be accepted.
  depends_on = [aws_s3_bucket_public_access_block.this]
}

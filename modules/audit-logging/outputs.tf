output "trail_arn" {
  description = "CloudTrail ARN."
  value       = aws_cloudtrail.this.arn
}

output "bucket_name" {
  description = "Log bucket name."
  value       = module.bucket.bucket_id
}

output "kms_key_arn" {
  description = "KMS key encrypting trail logs and the log group."
  value       = aws_kms_key.this.arn
}

output "log_group_name" {
  description = "CloudWatch log group receiving trail events (point your SIEM or metric filters here)."
  value       = aws_cloudwatch_log_group.this.name
}

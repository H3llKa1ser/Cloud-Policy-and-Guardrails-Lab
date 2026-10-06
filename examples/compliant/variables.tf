variable "offline" {
  description = "Plan without AWS credentials (lab mode)."
  type        = bool
  default     = true
}

variable "region" {
  description = "AWS region."
  type        = string
  default     = "eu-west-1"
}

variable "account_id" {
  description = "AWS account ID. The default is a placeholder for offline planning."
  type        = string
  default     = "123456789012"
}

variable "name_prefix" {
  description = "Prefix for globally unique names."
  type        = string
  default     = "guardrails-lab"
}

variable "ami_id" {
  description = "AMI for the app instance. Placeholder for offline planning; use a current hardened AMI for real deployments."
  type        = string
  default     = "ami-0123456789abcdef0"
}

variable "vpn_cidr" {
  description = "Corporate VPN range allowed to SSH to the app tier."
  type        = string
  default     = "10.250.0.0/16"
}

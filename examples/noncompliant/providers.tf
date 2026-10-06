terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

variable "offline" {
  description = "Plan without AWS credentials (lab mode). Never apply this stack."
  type        = bool
  default     = true
}

provider "aws" {
  region = "eu-west-1"

  access_key                  = var.offline ? "mock_access_key" : null
  secret_key                  = var.offline ? "mock_secret_key" : null
  skip_credentials_validation = var.offline
  skip_requesting_account_id  = var.offline
  skip_metadata_api_check     = var.offline

  default_tags {
    tags = {
      Owner              = "nobody-in-particular"
      Environment        = "lab"
      DataClassification = "internal"
    }
  }
}

# A second provider with no default tags, to demonstrate TAG_101.
provider "aws" {
  alias  = "untagged"
  region = "eu-west-1"

  access_key                  = var.offline ? "mock_access_key" : null
  secret_key                  = var.offline ? "mock_secret_key" : null
  skip_credentials_validation = var.offline
  skip_requesting_account_id  = var.offline
  skip_metadata_api_check     = var.offline
}

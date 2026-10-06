mock_provider "aws" {}

variables {
  name        = "app"
  description = "Application tier"
  vpc_id      = "vpc-0123456789abcdef0"
}

run "internal_ssh_is_allowed" {
  command = plan

  variables {
    ingress_rules = [{
      description = "SSH from corporate VPN"
      ip_protocol = "tcp"
      from_port   = 22
      to_port     = 22
      cidr_ipv4   = "10.20.0.0/16"
    }]
  }

  assert {
    condition     = length(aws_vpc_security_group_ingress_rule.this) == 1
    error_message = "Expected one ingress rule."
  }
}

run "public_https_is_allowed" {
  command = plan

  variables {
    ingress_rules = [{
      description = "HTTPS from internet"
      ip_protocol = "tcp"
      from_port   = 443
      to_port     = 443
      cidr_ipv4   = "0.0.0.0/0"
    }]
  }
}

run "public_ssh_is_rejected" {
  command = plan

  variables {
    ingress_rules = [{
      description = "SSH from anywhere"
      ip_protocol = "tcp"
      from_port   = 22
      to_port     = 22
      cidr_ipv4   = "0.0.0.0/0"
    }]
  }

  expect_failures = [var.ingress_rules]
}

run "public_ipv6_range_is_rejected" {
  command = plan

  variables {
    ingress_rules = [{
      description = "Wide range over IPv6"
      ip_protocol = "tcp"
      from_port   = 80
      to_port     = 443
      cidr_ipv6   = "::/0"
    }]
  }

  expect_failures = [var.ingress_rules]
}

run "public_all_traffic_is_rejected" {
  command = plan

  variables {
    ingress_rules = [{
      description = "Everything"
      ip_protocol = "-1"
      cidr_ipv4   = "0.0.0.0/0"
    }]
  }

  expect_failures = [var.ingress_rules]
}

run "rule_without_source_is_rejected" {
  command = plan

  variables {
    ingress_rules = [{
      description = "No source"
      ip_protocol = "tcp"
      from_port   = 8080
      to_port     = 8080
    }]
  }

  expect_failures = [var.ingress_rules]
}

run "default_egress_is_https_only" {
  command = plan

  assert {
    condition     = aws_vpc_security_group_egress_rule.this["HTTPS to anywhere"].from_port == 443
    error_message = "Default egress should be HTTPS only."
  }
}

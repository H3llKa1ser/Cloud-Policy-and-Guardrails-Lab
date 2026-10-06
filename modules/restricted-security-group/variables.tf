variable "name" {
  description = "Security group name."
  type        = string
}

variable "description" {
  description = "What this security group protects."
  type        = string
}

variable "vpc_id" {
  description = "VPC to create the security group in."
  type        = string
}

variable "public_ports" {
  description = "TCP ports that may be opened to the whole internet. Everything else is internal-only."
  type        = list(number)
  default     = [80, 443]
}

variable "ingress_rules" {
  description = "Ingress rules. Each needs a unique description and exactly one source."
  type = list(object({
    description                  = string
    ip_protocol                  = string
    from_port                    = optional(number)
    to_port                      = optional(number)
    cidr_ipv4                    = optional(string)
    cidr_ipv6                    = optional(string)
    referenced_security_group_id = optional(string)
    prefix_list_id               = optional(string)
  }))
  default = []

  validation {
    condition     = length(var.ingress_rules) == length(distinct([for r in var.ingress_rules : r.description]))
    error_message = "Each ingress rule needs a unique description (it is the rule's stable key and its audit trail)."
  }

  validation {
    condition = alltrue([for r in var.ingress_rules : length(compact([
      r.cidr_ipv4, r.cidr_ipv6, r.referenced_security_group_id, r.prefix_list_id
    ])) == 1])
    error_message = "Each ingress rule must have exactly one source: cidr_ipv4, cidr_ipv6, referenced_security_group_id or prefix_list_id."
  }

  # Shift-left: refuse internet exposure here, before a plan ever exists.
  # policies/aws/network.rego enforces the same thing for code that does
  # not use this module.
  validation {
    condition = alltrue([for r in var.ingress_rules :
      !contains(["0.0.0.0/0", "::/0"], coalesce(r.cidr_ipv4, r.cidr_ipv6, "internal")) || (
        lower(r.ip_protocol) == "tcp" &&
        r.from_port == r.to_port &&
        contains(var.public_ports, coalesce(r.from_port, -1))
      )
    ])
    error_message = "Internet-facing ingress (0.0.0.0/0 or ::/0) is only allowed for single TCP ports listed in public_ports."
  }
}

variable "egress_rules" {
  description = "Egress rules. Defaults to HTTPS only."
  type = list(object({
    description                  = string
    ip_protocol                  = string
    from_port                    = optional(number)
    to_port                      = optional(number)
    cidr_ipv4                    = optional(string)
    cidr_ipv6                    = optional(string)
    referenced_security_group_id = optional(string)
    prefix_list_id               = optional(string)
  }))
  default = [{
    description = "HTTPS to anywhere"
    ip_protocol = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_ipv4   = "0.0.0.0/0"
  }]

  validation {
    condition     = length(var.egress_rules) == length(distinct([for r in var.egress_rules : r.description]))
    error_message = "Each egress rule needs a unique description."
  }
}

variable "tags" {
  description = "Tags applied to every resource in the module."
  type        = map(string)
  default     = {}
}

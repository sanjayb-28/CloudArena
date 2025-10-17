variable "region" {
  description = "AWS region where the CloudArena sandbox resources are deployed."
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "Named AWS CLI profile used for authentication."
  type        = string
  default     = "arena"
}

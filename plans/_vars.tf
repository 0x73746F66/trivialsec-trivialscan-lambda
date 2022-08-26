variable "aws_access_key_id" {
  description = "AWS_ACCESS_KEY_ID"
  type        = string
}
variable "app_env" {
  description = "default Dev"
  type        = string
  default     = "Dev"
}
variable "app_name" {
  description = "default trivialsec"
  type        = string
  default     = "trivialscan-lambda"
}
variable "build_env" {
  description = "BUILD_ENV"
  type        = string
  default     = "development"
}

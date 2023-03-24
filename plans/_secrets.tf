variable "aws_secret_access_key" {
  description = "AWS_SECRET_ACCESS_KEY"
  type        = string
  sensitive   = true
}
variable "sendgrid_api_key" {
  description = "SENDGRID_API_KEY"
  type        = string
  sensitive   = true
}
variable "stripe_webhook_key" {
  description = "STRIPE_WEBHOOK_KEY"
  type        = string
  sensitive   = true
}
variable "stripe_secret_key" {
  description = "STRIPE_SECRET_KEY"
  type        = string
  sensitive   = true
}
variable "pusher_secret" {
  description = "PUSHER_SECRET"
  type        = string
  sensitive   = true
}
variable "dynatrace_token" {
  description = "DYNATRACE_TOKEN"
  type        = string
  sensitive   = true
}

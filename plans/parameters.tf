resource "aws_ssm_parameter" "sendgrid_api_key" {
  name        = "/${var.app_env}/${var.app_name}/Sendgrid/api-key"
  type        = "SecureString"
  value       = var.sendgrid_api_key
  tags        = local.tags
  overwrite   = true
}
resource "aws_ssm_parameter" "stripe_webhook_key" {
  name        = "/${var.app_env}/${var.app_name}/Stripe/webhook-key"
  type        = "SecureString"
  value       = var.stripe_webhook_key
  tags        = local.tags
  overwrite   = true
}
resource "aws_ssm_parameter" "stripe_secret_key" {
  name        = "/${var.app_env}/${var.app_name}/Stripe/secret-key"
  type        = "SecureString"
  value       = var.stripe_secret_key
  tags        = local.tags
  overwrite   = true
}

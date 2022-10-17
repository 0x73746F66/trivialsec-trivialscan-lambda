resource "aws_ssm_parameter" "trivialscan_lambda_url" {
  name        = "/${var.app_env}/Deploy/${var.app_name}/trivialscan_lambda_url"
  type        = "String"
  value       = aws_lambda_function_url.trivialscan.function_url
  tags        = local.tags
  overwrite   = true
}
resource "aws_ssm_parameter" "sendgrid_api_key" {
  name        = "/${var.app_env}/Deploy/${var.app_name}/sendgrid_api_key"
  type        = "SecureString"
  value       = var.sendgrid_api_key
  tags        = local.tags
  overwrite   = true
}
resource "aws_ssm_parameter" "stripe_webhook_key" {
  name        = "/${var.app_env}/Deploy/${var.app_name}/stripe_webhook_key"
  type        = "SecureString"
  value       = var.stripe_webhook_key
  tags        = local.tags
  overwrite   = true
}

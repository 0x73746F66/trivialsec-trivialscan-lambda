resource "aws_ssm_parameter" "trivialscan_lambda_url" {
  name        = "/${var.app_env}/Deploy/${var.app_name}/trivialscan_lambda_url"
  type        = "String"
  value       = aws_lambda_function_url.trivialscan.function_url
  tags = {
    CostCenter = "FOSS"
  }
  overwrite   = true
}

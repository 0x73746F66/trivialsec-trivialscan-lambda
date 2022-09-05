resource "aws_lambda_function" "trivialscan" {
  filename      = "${abspath(path.module)}/${local.source_file}"
  source_code_hash = filebase64sha256("${abspath(path.module)}/${local.source_file}")
  function_name = "${var.app_env}-trivialscan-api"
  role          = aws_iam_role.trivialscan_role.arn
  handler       = "app.handler"
  runtime       = local.python_version
  timeout       = 900

  environment {
    variables = {
      APP_ENV = var.app_env
      APP_NAME = var.app_name
      LOG_LEVEL = var.log_level
      STORE_BUCKET = data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket
    }
  }
  lifecycle {
    create_before_destroy = true
  }
  depends_on = [
    aws_iam_role_policy_attachment.policy_attach
  ]
  tags = {
    ProjectName = "trivialscan"
    ProjectLeadEmail = "chris@trivialsec.com"
    CostCenter = var.app_env != "Prod" ? "randd" : "opex"
    SecurityTags = "credentials,customer-data,public-data"
    AutomationTool = "Terraform"
  }
}

resource "aws_lambda_function_url" "trivialscan" {
  function_name      = aws_lambda_function.trivialscan.arn
  authorization_type = "NONE"
}

output "trivialscan_arn" {
    value = aws_lambda_function.trivialscan.arn
}
output "function_url" {
    value = aws_lambda_function_url.trivialscan.function_url
}

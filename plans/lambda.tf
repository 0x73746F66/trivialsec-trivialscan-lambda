resource "aws_lambda_function" "trivialscan" {
  s3_bucket     = aws_s3_object.file_upload.bucket
  s3_key        = aws_s3_object.file_upload.key
  source_code_hash = filebase64sha256("${abspath(path.module)}/${local.source_file}")
  function_name = local.function_name
  role          = aws_iam_role.trivialscan_role.arn
  handler       = "app.handler"
  runtime       = local.python_version
  timeout       = local.timeout
  memory_size   = local.memory_size
  layers        = var.app_env == "Prod" ? ["arn:aws:lambda:ap-southeast-2:725887861453:layer:Dynatrace_OneAgent_1_261_5_20230309-143152_python:1"] : []

  environment {
    variables = var.app_env == "Prod" ? {
      JITTER_SECONDS = var.jitter_seconds
      APP_ENV = var.app_env
      APP_NAME = var.app_name
      LOG_LEVEL = var.log_level
      STORE_BUCKET = data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket[0]
      AWS_LAMBDA_EXEC_WRAPPER = "/opt/dynatrace" # Use the wrapper from the layer
      DT_TENANT = "xuf85063"
      DT_CLUSTER_ID = "-1273248646"
      DT_CONNECTION_BASE_URL = "https://xuf85063.live.dynatrace.com"
      DT_CONNECTION_AUTH_TOKEN = var.dynatrace_token
      DT_OPEN_TELEMETRY_ENABLE_INTEGRATION = "true"
    } : {
      JITTER_SECONDS = var.jitter_seconds
      APP_ENV = var.app_env
      APP_NAME = var.app_name
      LOG_LEVEL = var.log_level
      STORE_BUCKET = data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket[0]
    }
  }
  lifecycle {
    create_before_destroy = true
  }
  depends_on = [
    aws_iam_role_policy_attachment.policy_attach
  ]
  tags = local.tags
}

resource "aws_lambda_function_url" "trivialscan" {
  function_name      = aws_lambda_function.trivialscan.arn
  authorization_type = "NONE"
}

resource "aws_cloudwatch_log_group" "api_logs" {
  skip_destroy      = var.app_env == "Prod"
  name              = "/aws/lambda/${aws_lambda_function.trivialscan.function_name}"
  retention_in_days = local.retention_in_days
}

resource "aws_s3_object" "file_upload" {
  bucket        = data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket[0]
  key           = "lambda-functions/${local.function_name}.zip"
  source        = "${abspath(path.module)}/${local.source_file}"
  content_type  = "application/octet-stream"
  etag          = filemd5("${abspath(path.module)}/${local.source_file}")
}

data "aws_iam_policy_document" "trivialscan_assume_role_policy" {
  statement {
    sid     = "${var.app_env}TrivialScanApiAssumeRole"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}
data "aws_iam_policy_document" "trivialscan_iam_policy" {
  statement {
    sid = "${var.app_env}TrivialScanApiLogging"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:${local.aws_default_region}:${local.aws_master_account_id}:log-group:/aws/lambda/${local.function_name}:*"
    ]
  }
  statement {
    sid = "${var.app_env}TrivialScanApiObjList"
    actions = [
      "s3:Head*",
      "s3:List*",
    ]
    resources = [
      "arn:aws:s3:::${data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket}",
      "arn:aws:s3:::${data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket}/*",
    ]
  }
  statement {
    sid = "${var.app_env}TrivialScanApiObjAccess"
    actions = [
      "s3:DeleteObject",
      "s3:GetObject",
      "s3:PutObject",
    ]
    resources = [
      "arn:aws:s3:::${data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket}/${var.app_env}/*",
    ]
  }
  statement {
    sid = "${var.app_env}TrivialScanSecrets"
    actions = [
      "ssm:GetParameter",
    ]
    resources = [
      "arn:aws:ssm:${local.aws_default_region}:${local.aws_master_account_id}:parameter/${var.app_env}/${var.app_name}/*",
    ]
  }
  statement {
    sid = "${var.app_env}TrivialScanDynamoDB"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:DeleteItem"
    ]
    resources = [
      "arn:aws:dynamodb:${local.aws_default_region}:${local.aws_master_account_id}:table/${lower(var.app_env)}_login_sessions",
      "arn:aws:dynamodb:${local.aws_default_region}:${local.aws_master_account_id}:table/${lower(var.app_env)}_member_fido",
      "arn:aws:dynamodb:${local.aws_default_region}:${local.aws_master_account_id}:table/${lower(var.app_env)}_report_history",
      "arn:aws:dynamodb:${local.aws_default_region}:${local.aws_master_account_id}:table/${lower(var.app_env)}_observed_identifiers",
      "arn:aws:dynamodb:${local.aws_default_region}:${local.aws_master_account_id}:table/${lower(var.app_env)}_early_warning_service",
      "arn:aws:dynamodb:${local.aws_default_region}:${local.aws_master_account_id}:table/${lower(var.app_env)}_findings",
    ]
  }
  statement {
    sid = "${var.app_env}TrivialScanDynamoDBQuery"
    actions = [
      "dynamodb:Query"
    ]
    resources = [
      "arn:aws:dynamodb:${local.aws_default_region}:${local.aws_master_account_id}:table/${lower(var.app_env)}_login_sessions/*",
      "arn:aws:dynamodb:${local.aws_default_region}:${local.aws_master_account_id}:table/${lower(var.app_env)}_member_fido/*",
      "arn:aws:dynamodb:${local.aws_default_region}:${local.aws_master_account_id}:table/${lower(var.app_env)}_report_history/*",
      "arn:aws:dynamodb:${local.aws_default_region}:${local.aws_master_account_id}:table/${lower(var.app_env)}_observed_identifiers/*",
      "arn:aws:dynamodb:${local.aws_default_region}:${local.aws_master_account_id}:table/${lower(var.app_env)}_early_warning_service/*",
      "arn:aws:dynamodb:${local.aws_default_region}:${local.aws_master_account_id}:table/${lower(var.app_env)}_findings/*",
    ]
  }
  statement {
    sid = "${var.app_env}TrivialScannerLambdaSQS"
    actions = [
      "sqs:SendMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:Get*",
    ]
    resources = [
      data.terraform_remote_state.reconnaissance_queue.outputs.reconnaissance_queue_arn,
      data.terraform_remote_state.subdomains_queue.outputs.subdomains_queue_arn
    ]
  }
}
resource "aws_iam_role" "trivialscan_role" {
  name               = "${lower(var.app_env)}_trivialscan_api_lambda_role"
  assume_role_policy = data.aws_iam_policy_document.trivialscan_assume_role_policy.json
  lifecycle {
    create_before_destroy = true
  }
}
resource "aws_iam_policy" "trivialscan_policy" {
  name   = "${lower(var.app_env)}_trivialscan_api_lambda_policy"
  path   = "/"
  policy = data.aws_iam_policy_document.trivialscan_iam_policy.json
}
resource "aws_iam_role_policy_attachment" "policy_attach" {
  role       = aws_iam_role.trivialscan_role.name
  policy_arn = aws_iam_policy.trivialscan_policy.arn
}

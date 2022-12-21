data "aws_iam_policy_document" "trivialscan_assume_role_policy" {
  statement {
    sid = "${var.app_env}TrivialScanApiAssumeRole"
    actions    = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}
data "aws_iam_policy_document" "trivialscan_iam_policy" {
  statement {
    sid = "${var.app_env}TrivialScanApiLogging"
    actions   = [
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
    actions   = [
      "s3:Head*",
      "s3:List*",
    ]
    resources = [
      "arn:aws:s3:::${data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket[0]}",
      "arn:aws:s3:::${data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket[0]}/*",
    ]
  }
  statement {
    sid = "${var.app_env}TrivialScanApiObjAccess"
    actions   = [
      "s3:DeleteObject",
      "s3:GetObject",
      "s3:PutObject",
    ]
    resources = [
      "arn:aws:s3:::${data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket[0]}/${var.app_env}/*",
    ]
  }
  statement {
    sid = "${var.app_env}TrivialScanSecrets"
    actions   = [
      "ssm:GetParameter",
    ]
    resources = [
      "arn:aws:ssm:${local.aws_default_region}:${local.aws_master_account_id}:parameter/${var.app_env}/${var.app_name}/*",
    ]
  }
  statement {
    sid = "${var.app_env}TrivialScannerLambdaSQS"
    actions   = [
      "sqs:SendMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:Get*",
    ]
    resources = [
      data.terraform_remote_state.trivialscan_sqs.outputs.reconnaissance_queue_arn
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
  name        = "${lower(var.app_env)}_trivialscan_api_lambda_policy"
  path        = "/"
  policy      = data.aws_iam_policy_document.trivialscan_iam_policy.json
}
resource "aws_iam_role_policy_attachment" "policy_attach" {
  role       = aws_iam_role.trivialscan_role.name
  policy_arn = aws_iam_policy.trivialscan_policy.arn
}

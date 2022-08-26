resource "aws_iam_role" "trivialscan_role" {
  name               = "trivialscan_lambda_role"
  assume_role_policy = file("${path.module}/policy/trivialscan_policy.json")
  lifecycle {
    create_before_destroy = true
  }
}
resource "aws_iam_policy" "trivialscan_policy" {
  name        = "trivialscan_lambda_policy"
  path        = "/"
  policy      = templatefile("${path.module}/policy/trivialscan_role_policy.json", {
    store_bucket = data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket
    app_env = var.app_env
    app_name = var.app_name
  })
}
resource "aws_iam_role_policy_attachment" "policy_attach" {
  role       = aws_iam_role.trivialscan_role.name
  policy_arn = aws_iam_policy.trivialscan_policy.arn
}

output "trivialscan_role" {
  value = aws_iam_role.trivialscan_role.name
}

output "trivialscan_role_arn" {
  value = aws_iam_role.trivialscan_role.arn
}

output "trivialscan_policy_arn" {
  value = aws_iam_policy.trivialscan_policy.arn
}

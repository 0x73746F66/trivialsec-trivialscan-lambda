output "trivialscan_arn" {
  value = aws_lambda_function.trivialscan.arn
}
output "function_url" {
  value = aws_lambda_function_url.trivialscan.function_url
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


resource "aws_route53_record" "dns_cname" {
  zone_id = local.hosted_zone
  name    = local.domain_name
  type    = "CNAME"
  ttl     = 15
  records = [aws_lambda_function_url.trivialscan.function_url]
}


resource "aws_cloudfront_distribution" "trivialscan_api" {
  depends_on = [
    aws_lambda_function.trivialscan
  ]
  wait_for_deployment = false
  origin {
    domain_name = "${aws_lambda_function_url.trivialscan.url_id}.lambda-url.${local.aws_default_region}.on.aws"
    origin_id = join("", regexall("[[:alnum:]]+", aws_lambda_function_url.trivialscan.url_id))
    custom_origin_config {
      http_port = "80"
      https_port = "443"
      origin_protocol_policy = "https-only"
      origin_ssl_protocols = ["TLSv1.1", "TLSv1.2"]
    }
  }
  enabled             = true
  is_ipv6_enabled     = true
  price_class = "PriceClass_100"
  aliases = [
    local.domain_name
  ]
  default_cache_behavior {
    allowed_methods  = ["HEAD", "DELETE", "POST", "GET", "OPTIONS", "PUT", "PATCH"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = join("", regexall("[[:alnum:]]+", aws_lambda_function_url.trivialscan.url_id))
    compress         = true
    forwarded_values {
      query_string = true

      cookies {
        forward = "none"
      }
    }
    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 0
    max_ttl                = 0
  }
  restrictions {
    geo_restriction {
      restriction_type = "blacklist"
      locations        = ["UA", "RU", "CN", "VN", "TH", "KP", "IR", "IQ", "IN", "NG", "SO", "SS", "YE", "ZM", "ZW", "AF", "BA", "BD", "CG", "CU", "CZ", "DM", "DO", "DZ", "ET", "GT", "GU", "HN", "HT"]
    }
  }
  viewer_certificate {
    acm_certificate_arn            = local.acm_arn
    cloudfront_default_certificate = false
    minimum_protocol_version       = "TLSv1.2_2019"
    ssl_support_method             = "sni-only"
  }
  tags = local.tags
}


resource "aws_cloudfront_response_headers_policy" "security_headers_policy" {
  name = "${var.app_env}ApiSecurityHeadersPolicy"

  cors_config {
    access_control_allow_credentials = true

    access_control_allow_headers {
      items = [
        "Authorization",
        "X-Trivialscan-Account",
        "X-Trivialscan-Version",
      ]
    }

    access_control_allow_methods {
      items = [
        "DELETE", "POST", "GET", "OPTIONS",
      ]
    }

    access_control_allow_origins {
      items = [
        "https://www.trivialsec.com",
        "http://100.73.142.90:5173",
        "http://localhost:5173",
      ]
    }

    origin_override = true
  }

  security_headers_config {
    content_type_options {
      override = true
    }
    frame_options {
      frame_option = "DENY"
      override = true
    }
    referrer_policy {
      referrer_policy = "same-origin"
      override = true
    }
    strict_transport_security {
      access_control_max_age_sec = "31536000"
      include_subdomains = true
      preload = true
      override = true
    }
    content_security_policy {
      content_security_policy = join("; ", [
        "frame-ancestors 'none'",
        "default-src 'self'",
        "img-src 'self' https://fastapi.tiangolo.com https://cdn.redoc.ly data:",
        "script-src 'self' https://www.gstatic.com https://www.google.com",
        "script-src-elem https://cdn.jsdelivr.net",
        "font-src 'self' https://fonts.gstatic.com",
        "object-src 'none'",
        "form-action 'none'",
        "worker-src blob:",
        "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'",
        "style-src-attr 'sha256-pILX+5FGCpLRHvNBgtABIdSMmytrYudGxJBUYXY1t0s=' 'sha256-wK4n87cEV+DaOorOySn50J1N+etqDZQSmu9zgJp4nu4='",
        "connect-src 'self' ${local.domain_name}",
      ])
      override = true
    }
  }
}

resource "aws_cloudfront_origin_request_policy" "origin_request_policy" {
  name    = "${var.app_env}ApiOriginRequestPolicy"

  cookies_config {
    cookie_behavior = "none"
  }
  headers_config {
    header_behavior = "whitelist"
    headers {
      items = [
        "User-Agent",
        "X-Trivialscan-Account",
        "X-Trivialscan-Version",
      ]
    }
  }
  query_strings_config {
    query_string_behavior = "all"
  }
}

resource "aws_cloudfront_cache_policy" "cache_policy" {
  name        = "${var.app_env}ApiCachePolicy"

  default_ttl = 15
  max_ttl     = 30
  min_ttl     = 0
  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "none"
    }
    headers_config {
      header_behavior = "whitelist"
      headers {
        items = ["Authorization"]
      }
    }
    query_strings_config {
      query_string_behavior = "all"
    }
  }
}

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
    response_headers_policy_id  = aws_cloudfront_response_headers_policy.security_headers_policy.id
    cache_policy_id             = aws_cloudfront_cache_policy.cache_policy.id
    origin_request_policy_id    = aws_cloudfront_origin_request_policy.origin_request_policy.id
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

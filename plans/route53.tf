resource "aws_route53_record" "dns_a" {
    zone_id = local.hosted_zone
    name    = local.domain_name
    type    = "A"

    alias {
        name                   = aws_cloudfront_distribution.trivialscan_api.domain_name
        zone_id                = aws_cloudfront_distribution.trivialscan_api.hosted_zone_id
        evaluate_target_health = false
    }
}

resource "aws_route53_record" "dns_aaaa" {
    zone_id = local.hosted_zone
    name    = local.domain_name
    type    = "AAAA"

    alias {
        name                   = aws_cloudfront_distribution.trivialscan_api.domain_name
        zone_id                = aws_cloudfront_distribution.trivialscan_api.hosted_zone_id
        evaluate_target_health = false
    }
}

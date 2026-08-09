# ─── ACM Certificate ──────────────────────────────────────────────────────────
#
# Issues a public TLS certificate via AWS Certificate Manager for the provided
# domain. DNS validation is the recommended method — it auto-renews without
# manual email approval.
#
# Two modes:
#   a) var.acm_certificate_arn is set → use a pre-existing cert (no resources created)
#   b) var.domain_name is set         → create a new cert + optional Route 53 records

resource "aws_acm_certificate" "agentwall" {
  count = var.acm_certificate_arn == "" && var.domain_name != "" ? 1 : 0

  domain_name               = var.domain_name
  validation_method         = "DNS"
  subject_alternative_names = ["*.${var.domain_name}"]

  # Must be created before the old cert is destroyed during renewals
  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "${var.cluster_name}-tls"
  }
}

# ─── Route 53 DNS Validation Records (optional) ───────────────────────────────
#
# Only created when create_route53_records = true AND a Route 53 hosted zone
# ID is provided. If you manage DNS outside AWS, set create_route53_records=false
# and add the CNAME records manually using the acm_validation_records output.

resource "aws_route53_record" "acm_validation" {
  for_each = (
    var.create_route53_records &&
    var.route53_zone_id != "" &&
    var.acm_certificate_arn == "" &&
    var.domain_name != ""
  ) ? {
    for dvo in aws_acm_certificate.agentwall[0].domain_validation_options :
    dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = var.route53_zone_id
}

resource "aws_acm_certificate_validation" "agentwall" {
  count = (
    var.create_route53_records &&
    var.route53_zone_id != "" &&
    var.acm_certificate_arn == "" &&
    var.domain_name != ""
  ) ? 1 : 0

  certificate_arn         = aws_acm_certificate.agentwall[0].arn
  validation_record_fqdns = [for r in aws_route53_record.acm_validation : r.fqdn]
}

# ─── Resolved certificate ARN ─────────────────────────────────────────────────
#
# Other resources (ALB Ingress annotation, outputs) consume this local.
# Priority: explicit ARN var > newly created cert > empty string.

locals {
  resolved_acm_certificate_arn = (
    var.acm_certificate_arn != "" ? var.acm_certificate_arn :
    length(aws_acm_certificate.agentwall) > 0 ? aws_acm_certificate.agentwall[0].arn :
    ""
  )
}

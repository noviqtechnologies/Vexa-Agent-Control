# ─── ECR Repositories ─────────────────────────────────────────────────────────

locals {
  ecr_image_map = {
    "agentwall"                    = "gateway.image.repository"
    "agentwall-operator"           = "operator.image.repository"
    "agentwall-dashboard-api"      = "dashboardApi.image.repository"
    "agentwall-dashboard-frontend" = "dashboardFrontend.image.repository"
  }

  ecr_repository_names = var.ecr_enabled ? keys(local.ecr_image_map) : []
  ecr_base_url         = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com"
}

resource "aws_ecr_repository" "agentwall" {
  for_each = toset(local.ecr_repository_names)

  name                 = each.key
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    Name = each.key
  }
}

# ─── Lifecycle Policy — keep the last 10 tagged images per repo ───────────────

resource "aws_ecr_lifecycle_policy" "agentwall" {
  for_each   = aws_ecr_repository.agentwall
  repository = each.value.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images older than 14 days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 14
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Keep last 10 tagged releases"
        selection = {
          tagStatus   = "tagged"
          tagPrefixList = ["v", "latest"]
          countType   = "imageCountMoreThan"
          countNumber = 10
        }
        action = { type = "expire" }
      }
    ]
  })
}

# ─── ECR Repository Policy — allow pull from Fargate Pod Execution Role ───────

resource "aws_ecr_repository_policy" "agentwall" {
  for_each   = aws_ecr_repository.agentwall
  repository = each.value.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowFargatePodPull"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.fargate.arn
        }
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability"
        ]
      }
    ]
  })
}

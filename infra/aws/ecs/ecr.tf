# ─── Amazon Elastic Container Registry (ECR) — Optional Private Registry ─────
# Provisions private ECR repositories with automated pruning lifecycle policies (FR-5).
# Equivalent to Artifact Registry in GCP and ACR in Azure. Disabled by default to use GHCR.

locals {
  ecr_repositories = var.ecr_enabled ? toset([
    "gateway",
    "dashboard-api",
    "control-plane-ui",
    "agentcontrol-db"
  ]) : toset([])
}

resource "aws_ecr_repository" "repos" {
  for_each             = local.ecr_repositories
  name                 = "${local.name_prefix}/${each.key}"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name = "${local.name_prefix}-${each.key}-ecr"
  }
}

# Lifecycle Policy: Keep only the 2 most recent tagged images, delete untagged after 1 day
resource "aws_ecr_lifecycle_policy" "repo_policy" {
  for_each   = local.ecr_repositories
  repository = aws_ecr_repository.repos[each.key].name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images older than 1 day"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 1
        }
        action = {
          type = "expire"
        }
      },
      {
        rulePriority = 2
        description  = "Keep only 2 most recent tagged images"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["v", "sha-", "prod-", "stage-", "dev-", "release-"]
          countType     = "imageCountMoreThan"
          countNumber   = 2
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

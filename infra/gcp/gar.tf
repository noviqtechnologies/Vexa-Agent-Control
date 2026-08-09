# ─── Google Artifact Registry (GAR) — Optional Private Container Registry ────
# Equivalent to AWS ECR and Azure ACR. Disabled by default to use public GHCR images.

locals {
  gar_repo_name = replace("gar-${local.name_prefix}-${random_string.suffix.result}", "_", "-")
}

resource "google_artifact_registry_repository" "repo" {
  count         = var.gar_enabled ? 1 : 0
  project       = var.gcp_project_id
  location      = var.gcp_region
  repository_id = local.gar_repo_name
  description   = "Private Docker repository for AgentWall container images"
  format        = "DOCKER"

  labels = local.default_labels

  depends_on = [google_project_service.artifactregistry]
}

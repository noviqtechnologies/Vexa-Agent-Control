# ─── Artifact Registry Repository & IAM Permissions ───────────────────────────
# Dedicated Artifact Registry Docker repository with automated lifecycle pruning policies.

data "google_project" "current" {
  count      = var.gcp_project_number == null ? 1 : 0
  project_id = var.gcp_project_id
}

locals {
  effective_project_number = var.gcp_project_number != null ? tostring(var.gcp_project_number) : data.google_project.current[0].number
  repo_id                  = length(google_artifact_registry_repository.agentcontrol_repo) > 0 ? google_artifact_registry_repository.agentcontrol_repo[0].repository_id : "agentcontrol-${var.environment}"
}

resource "google_artifact_registry_repository" "agentcontrol_repo" {
  count         = var.gar_enabled ? 1 : 0
  location      = var.gcp_region
  repository_id = "agentcontrol-${var.environment}"
  description   = "AgentControl ${var.environment} Container Repository"
  format        = "DOCKER"
  project       = var.gcp_project_id

  # Cost Optimization: Auto-prune old image layers to prevent storage accumulation
  cleanup_policies {
    id     = "keep-recent-tagged"
    action = "KEEP"
    most_recent_versions {
      keep_count = 2
    }
  }

  cleanup_policies {
    id     = "delete-old-untagged"
    action = "DELETE"
    condition {
      tag_state  = "UNTAGGED"
      older_than = "86400s" # 1 day
    }
  }

  depends_on = [google_project_service.apis]
}

resource "google_project_iam_member" "artifact_registry_reader_sa" {
  project = var.gcp_project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.cloud_run_sa.email}"
}

resource "google_project_iam_member" "artifact_registry_reader_agent" {
  project = var.gcp_project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:service-${local.effective_project_number}@serverless-robot-prod.iam.gserviceaccount.com"
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region

  default_labels = local.default_labels
}

provider "random" {}

# ─── Unique Suffix & Local Values ─────────────────────────────────────────────

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

# Auto-generate secure random secrets if not explicitly provided
resource "random_password" "gateway_secret" {
  length  = 32
  special = false
}

resource "random_password" "policy_read_secret" {
  length  = 32
  special = false
}

resource "random_password" "postgres_password" {
  length  = 24
  special = false
}

resource "random_id" "encryption_secret" {
  byte_length = 32
}

locals {
  name_prefix = "agentwall-${var.environment}"

  gateway_secret     = var.gateway_secret != "" ? var.gateway_secret : random_password.gateway_secret.result
  policy_read_secret = var.policy_read_secret != "" ? var.policy_read_secret : random_password.policy_read_secret.result
  postgres_password  = var.postgres_password != "" ? var.postgres_password : random_password.postgres_password.result
  encryption_secret  = var.encryption_secret != "" ? var.encryption_secret : random_id.encryption_secret.hex

  default_labels = merge({
    project     = "agentwall"
    environment = var.environment
    managed_by  = "terraform"
  }, var.labels)
}

# ─── Required GCP Service APIs ────────────────────────────────────────────────

resource "google_project_service" "run" {
  project                    = var.gcp_project_id
  service                    = "run.googleapis.com"
  disable_on_destroy         = false
  disable_dependent_services = false
}

resource "google_project_service" "secretmanager" {
  project                    = var.gcp_project_id
  service                    = "secretmanager.googleapis.com"
  disable_on_destroy         = false
  disable_dependent_services = false
}

resource "google_project_service" "artifactregistry" {
  count                      = var.gar_enabled ? 1 : 0
  project                    = var.gcp_project_id
  service                    = "artifactregistry.googleapis.com"
  disable_on_destroy         = false
  disable_dependent_services = false
}

resource "google_project_service" "compute" {
  count                      = var.enable_vpc ? 1 : 0
  project                    = var.gcp_project_id
  service                    = "compute.googleapis.com"
  disable_on_destroy         = false
  disable_dependent_services = false
}

resource "google_project_service" "vpcaccess" {
  count                      = var.enable_vpc ? 1 : 0
  project                    = var.gcp_project_id
  service                    = "vpcaccess.googleapis.com"
  disable_on_destroy         = false
  disable_dependent_services = false
}

# ─── Cloud Run Dedicated Service Account & IAM ────────────────────────────────

resource "google_service_account" "cloud_run_sa" {
  project      = var.gcp_project_id
  account_id   = "agentwall-runner-${random_string.suffix.result}"
  display_name = "AgentWall Cloud Run Service Account"
  description  = "Dedicated runtime service account for AgentWall gateway and control plane services"
}

resource "google_project_iam_member" "log_writer" {
  project = var.gcp_project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.cloud_run_sa.email}"
}

resource "google_project_iam_member" "metric_writer" {
  project = var.gcp_project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.cloud_run_sa.email}"
}

resource "google_project_iam_member" "secret_accessor" {
  project = var.gcp_project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.cloud_run_sa.email}"
}

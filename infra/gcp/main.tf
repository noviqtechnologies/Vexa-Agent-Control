provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region

  default_labels = local.default_labels
}

provider "google-beta" {
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

locals {
  name_prefix = "agentcontrol-${var.environment}"

  default_labels = merge({
    project     = "agentcontrol"
    environment = var.environment
    managed_by  = "terraform"
  }, var.labels)

  base_gcp_services = [
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudbuild.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "iam.googleapis.com"
  ]

  vpc_gcp_services = var.enable_vpc ? [
    "compute.googleapis.com",
    "vpcaccess.googleapis.com"
  ] : []

  cloud_sql_services = var.enable_cloud_sql ? [
    "sqladmin.googleapis.com"
  ] : []

  gcp_services = concat(local.base_gcp_services, local.vpc_gcp_services, local.cloud_sql_services)
}

# ─── Required GCP Service APIs ────────────────────────────────────────────────

resource "google_project_service" "apis" {
  for_each                   = toset(local.gcp_services)
  project                    = var.gcp_project_id
  service                    = each.key
  disable_on_destroy         = false
  disable_dependent_services = false

  lifecycle {
    ignore_changes = all
  }
}

# ─── Cloud Run Dedicated Service Account & IAM ────────────────────────────────

resource "google_service_account" "cloud_run_sa" {
  project      = var.gcp_project_id
  account_id   = "agentcontrol-runner-${random_string.suffix.result}"
  display_name = "AgentControl Cloud Run Service Account"
  description  = "Dedicated runtime service account for AgentControl gateway and control plane services"

  depends_on = [google_project_service.apis]
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

resource "google_project_iam_member" "cloudsql_client" {
  count   = var.enable_cloud_sql ? 1 : 0
  project = var.gcp_project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.cloud_run_sa.email}"
}

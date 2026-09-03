# ─── Random Secret Generators ─────────────────────────────────────────────────
# Generates stable cryptographic tokens stored in Secret Manager.

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

resource "random_password" "session_secret" {
  length  = 32
  special = false
}

locals {
  effective_gateway_secret     = var.gateway_secret != "" ? var.gateway_secret : random_password.gateway_secret.result
  effective_policy_read_secret = var.policy_read_secret != "" ? var.policy_read_secret : random_password.policy_read_secret.result
  effective_postgres_password  = var.postgres_password != "" ? var.postgres_password : random_password.postgres_password.result
  effective_encryption_secret  = var.encryption_secret != "" ? var.encryption_secret : random_id.encryption_secret.hex
  effective_session_secret     = var.session_secret != "" ? var.session_secret : random_password.session_secret.result
}

# ─── Secret Manager Secrets & Versions ────────────────────────────────────────

# 1. Database Connection URL
resource "google_secret_manager_secret" "db_credentials" {
  secret_id = "${local.name_prefix}-db-conn"
  project   = var.gcp_project_id

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "db_credentials" {
  secret      = google_secret_manager_secret.db_credentials.id
  secret_data = var.database_url != "" ? var.database_url : "postgres://${var.postgres_user}:${local.effective_postgres_password}@127.0.0.1:5432/${var.postgres_db}?sslmode=disable"
}

# 2. Gateway Ingest Secret
resource "google_secret_manager_secret" "gateway_secret" {
  secret_id = "${local.name_prefix}-gateway-secret"
  project   = var.gcp_project_id

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "gateway_secret" {
  secret      = google_secret_manager_secret.gateway_secret.id
  secret_data = local.effective_gateway_secret
}

# 3. Policy Read Secret
resource "google_secret_manager_secret" "policy_read_secret" {
  secret_id = "${local.name_prefix}-policy-read-secret"
  project   = var.gcp_project_id

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "policy_read_secret" {
  secret      = google_secret_manager_secret.policy_read_secret.id
  secret_data = local.effective_policy_read_secret
}

# 4. Master Provider Encryption Key (32-byte hex)
resource "google_secret_manager_secret" "encryption_secret" {
  secret_id = "${local.name_prefix}-encryption-secret"
  project   = var.gcp_project_id

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "encryption_secret" {
  secret      = google_secret_manager_secret.encryption_secret.id
  secret_data = local.effective_encryption_secret
}

# 5. Session Signing Secret
resource "google_secret_manager_secret" "session_secret" {
  secret_id = "${local.name_prefix}-session-secret"
  project   = var.gcp_project_id

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "session_secret" {
  secret      = google_secret_manager_secret.session_secret.id
  secret_data = local.effective_session_secret
}

# ─── Cloud SQL Database (Persistent PostgreSQL 16) ────────────────────────────
# Provisions a managed Cloud SQL instance to guarantee permanent durability for
# provider API keys, virtual keys, audit events, and spend analytics.
# Eliminates data loss across Cloud Run revisions and scale-to-zero restarts.

resource "random_password" "cloud_sql_password" {
  count   = var.enable_cloud_sql ? 1 : 0
  length  = 24
  special = false
}

resource "google_sql_database_instance" "postgres" {
  count               = var.enable_cloud_sql ? 1 : 0
  name                = "${local.name_prefix}-pg-${random_string.suffix.result}"
  database_version    = "POSTGRES_16"
  region              = var.gcp_region
  project             = var.gcp_project_id
  deletion_protection = var.environment == "prod" ? true : false

  settings {
    tier              = var.cloud_sql_tier
    edition           = "ENTERPRISE"
    disk_size         = var.cloud_sql_disk_size_gb
    disk_type         = "PD_SSD"
    disk_autoresize   = false
    availability_type = "ZONAL"

    backup_configuration {
      enabled                        = false
      point_in_time_recovery_enabled = false
    }

    ip_configuration {
      ipv4_enabled = true
    }

    database_flags {
      name  = "log_min_messages"
      value = "warning"
    }

    insights_config {
      query_insights_enabled = false
    }
  }

  depends_on = [google_project_service.apis]
}

resource "google_sql_database" "agentcontrol" {
  count     = var.enable_cloud_sql ? 1 : 0
  name      = var.postgres_db
  instance  = google_sql_database_instance.postgres[0].name
  project   = var.gcp_project_id
  charset   = "UTF8"
  collation = "en_US.UTF8"
}

resource "google_sql_user" "agentcontrol" {
  count    = var.enable_cloud_sql ? 1 : 0
  name     = var.postgres_user
  instance = google_sql_database_instance.postgres[0].name
  password = random_password.cloud_sql_password[0].result
  project  = var.gcp_project_id
}

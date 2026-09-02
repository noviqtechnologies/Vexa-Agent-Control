# ─── Locals for Cloud Run Inter-Service Resolution ────────────────────────────

locals {
  effective_gateway_url = var.gateway_url != "" ? var.gateway_url : "https://${local.name_prefix}-gateway-${local.effective_project_number}.${var.gcp_region}.run.app"
}

# ─── 1. Enterprise Control Plane Dashboard API & Database ─────────────────────
# Multi-container Cloud Run revision housing the REST API and PostgreSQL sidecar.

resource "google_cloud_run_v2_service" "api" {
  name                = "${local.name_prefix}-api"
  location            = var.gcp_region
  ingress             = "INGRESS_TRAFFIC_ALL"
  project             = var.gcp_project_id
  deletion_protection = var.deletion_protection

  template {
    service_account = google_service_account.cloud_run_sa.email

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    dynamic "vpc_access" {
      for_each = var.enable_vpc ? [1] : []
      content {
        connector = google_vpc_access_connector.connector[0].id
        egress    = "ALL_TRAFFIC"
      }
    }

    # Primary Ingress Container: Dashboard API
    containers {
      name  = "dashboard-api"
      image = var.control_plane_api_image

      ports {
        container_port = 8400
      }

      resources {
        limits = {
          cpu    = var.api_cpu
          memory = var.api_memory
        }
        cpu_idle          = false
        startup_cpu_boost = true
      }

      env {
        name = "DATABASE_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.db_credentials.secret_id
            version = "latest"
          }
        }
      }
      env {
        name  = "VALKEY_URL"
        value = "127.0.0.1:6379"
      }
      env {
        name  = "DASHBOARD_PORT"
        value = "8400"
      }
      env {
        name  = "ENVIRONMENT"
        value = var.environment
      }
      env {
        name  = "DEV_MODE"
        value = var.environment == "dev" ? "true" : "false"
      }
      env {
        name  = "ALLOW_DEV_MODE"
        value = var.environment == "dev" ? "true" : "false"
      }
      env {
        name = "GATEWAY_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.gateway_secret.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "POLICY_READ_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.policy_read_secret.secret_id
            version = "latest"
          }
        }
      }
      env {
        name  = "GATEWAY_URL"
        value = local.effective_gateway_url
      }
      env {
        name = "PROVIDER_KEY_ENCRYPTION_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.encryption_secret.secret_id
            version = "latest"
          }
        }
      }
      env {
        name  = "DIRECT_TLS_ENABLED"
        value = "true"
      }
      env {
        name = "INGRESS_AUTH_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.gateway_secret.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "AGENTWALL_SESSION_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.session_secret.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "AGENTCONTROL_SESSION_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.session_secret.secret_id
            version = "latest"
          }
        }
      }

      startup_probe {
        http_get {
          path = "/healthz"
          port = 8400
        }
        initial_delay_seconds = 3
        period_seconds        = 5
        failure_threshold     = 24
        timeout_seconds       = 4
      }

      liveness_probe {
        http_get {
          path = "/healthz"
          port = 8400
        }
        period_seconds    = 15
        failure_threshold = 3
        timeout_seconds   = 3
      }
    }

    # Sidecar Container: PostgreSQL Engine with Automatic Migrations
    containers {
      name  = "postgres"
      image = var.control_plane_db_image

      resources {
        limits = {
          cpu    = var.db_cpu
          memory = var.db_memory
        }
        cpu_idle          = false
        startup_cpu_boost = true
      }

      env {
        name  = "POSTGRES_USER"
        value = var.postgres_user
      }
      env {
        name  = "POSTGRES_PASSWORD"
        value = local.effective_postgres_password
      }
      env {
        name  = "POSTGRES_DB"
        value = var.postgres_db
      }

      startup_probe {
        tcp_socket {
          port = 5432
        }
        initial_delay_seconds = 3
        period_seconds        = 5
        failure_threshold     = 24
        timeout_seconds       = 3
      }
    }

    # Sidecar Container: Valkey Distributed Caching Engine
    containers {
      name  = "valkey"
      image = "valkey/valkey:7.2-alpine"

      resources {
        limits = {
          cpu    = "0.25"
          memory = "256Mi"
        }
        cpu_idle = false
      }

      startup_probe {
        tcp_socket {
          port = 6379
        }
        initial_delay_seconds = 2
        period_seconds        = 5
        failure_threshold     = 12
      }
    }
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }

  depends_on = [
    google_project_service.apis,
    google_secret_manager_secret_version.db_credentials,
    google_secret_manager_secret_version.gateway_secret,
    google_secret_manager_secret_version.policy_read_secret,
    google_secret_manager_secret_version.encryption_secret,
    google_secret_manager_secret_version.session_secret,
    google_project_iam_member.artifact_registry_reader_sa,
    google_project_iam_member.artifact_registry_reader_agent
  ]
}

# ─── 2. Enterprise Control Plane Frontend UI ──────────────────────────────────
# Web portal for SOC teams, policy administration, and telemetry dashboards.

resource "google_cloud_run_v2_service" "ui" {
  name                = "${local.name_prefix}-ui"
  location            = var.gcp_region
  ingress             = "INGRESS_TRAFFIC_ALL"
  project             = var.gcp_project_id
  deletion_protection = var.deletion_protection

  template {
    service_account = google_service_account.cloud_run_sa.email

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    dynamic "vpc_access" {
      for_each = var.enable_vpc ? [1] : []
      content {
        connector = google_vpc_access_connector.connector[0].id
        egress    = "ALL_TRAFFIC"
      }
    }

    containers {
      name  = "control-plane-ui"
      image = var.control_plane_ui_image

      ports {
        container_port = 80
      }

      resources {
        limits = {
          cpu    = var.ui_cpu
          memory = var.ui_memory
        }
        cpu_idle          = true
        startup_cpu_boost = true
      }

      env {
        name  = "AGENTCONTROL_API_URL"
        value = google_cloud_run_v2_service.api.uri
      }

      env {
        name  = "AGENTCONTROL_API_UPSTREAM"
        value = replace(replace(google_cloud_run_v2_service.api.uri, "https://", ""), "http://", "")
      }

      env {
        name  = "DASHBOARD_API_URL"
        value = google_cloud_run_v2_service.api.uri
      }

      startup_probe {
        http_get {
          path = "/"
          port = 80
        }
        initial_delay_seconds = 3
        period_seconds        = 5
        failure_threshold     = 24
        timeout_seconds       = 4
      }

      liveness_probe {
        http_get {
          path = "/"
          port = 80
        }
        period_seconds    = 15
        failure_threshold = 3
        timeout_seconds   = 4
      }
    }
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }

  depends_on = [
    google_project_service.apis,
    google_cloud_run_v2_service.api,
    google_project_iam_member.artifact_registry_reader_sa,
    google_project_iam_member.artifact_registry_reader_agent
  ]
}

# ─── 3. AgentWall Gateway Proxy (Core Enforcement Engine) ─────────────────────
# High-performance Rust reverse proxy intercepting & policy-checking MCP calls.

resource "google_cloud_run_v2_service" "gateway" {
  name                = "${local.name_prefix}-gateway"
  location            = var.gcp_region
  ingress             = "INGRESS_TRAFFIC_ALL"
  project             = var.gcp_project_id
  deletion_protection = var.deletion_protection

  template {
    service_account = google_service_account.cloud_run_sa.email

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    dynamic "vpc_access" {
      for_each = var.enable_vpc ? [1] : []
      content {
        connector = google_vpc_access_connector.connector[0].id
        egress    = "ALL_TRAFFIC"
      }
    }

    containers {
      name  = "gateway"
      image = var.container_image

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = var.gateway_cpu
          memory = var.gateway_memory
        }
        cpu_idle          = false
        startup_cpu_boost = true
      }

      env {
        name  = "AGENTCONTROL_LISTEN"
        value = "0.0.0.0:8080"
      }
      env {
        name  = "AGENTWALL_LISTEN"
        value = "0.0.0.0:8080"
      }
      env {
        name  = "AGENTCONTROL_CENTRALIZED"
        value = "true"
      }
      env {
        name = "AGENTCONTROL_ADMIN_TOKEN"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.gateway_secret.secret_id
            version = "latest"
          }
        }
      }
      env {
        name  = "AGENTCONTROL_POLICY_PATH"
        value = "/app/policy.example.yaml"
      }
      env {
        name  = "AGENTCONTROL_HUB_URL"
        value = google_cloud_run_v2_service.api.uri
      }
      env {
        name  = "DASHBOARD_API_URL"
        value = google_cloud_run_v2_service.api.uri
      }
      env {
        name = "POLICY_READ_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.policy_read_secret.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "GATEWAY_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.gateway_secret.secret_id
            version = "latest"
          }
        }
      }
      env {
        name  = "POLICY_POLL_INTERVAL_SECS"
        value = "30"
      }
      env {
        name  = "AGENTCONTROL_LOG_PATH"
        value = "/var/log/agentcontrol/audit.log"
      }
      env {
        name  = "AGENTWALL_LOG_PATH"
        value = "/var/log/agentcontrol/audit.log"
      }

      startup_probe {
        http_get {
          path = "/healthz"
          port = 8080
        }
        initial_delay_seconds = 3
        period_seconds        = 5
        failure_threshold     = 24
        timeout_seconds       = 4
      }

      liveness_probe {
        http_get {
          path = "/healthz"
          port = 8080
        }
        period_seconds    = 15
        failure_threshold = 3
        timeout_seconds   = 4
      }
    }
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }

  depends_on = [
    google_project_service.apis,
    google_cloud_run_v2_service.api,
    google_secret_manager_secret_version.policy_read_secret,
    google_secret_manager_secret_version.gateway_secret,
    google_project_iam_member.artifact_registry_reader_sa,
    google_project_iam_member.artifact_registry_reader_agent
  ]
}

# ─── Public Invocation IAM Permissions (Roles: roles/run.invoker) ─────────────

resource "google_cloud_run_v2_service_iam_member" "api_public" {
  count    = var.allow_unauthenticated ? 1 : 0
  project  = var.gcp_project_id
  location = google_cloud_run_v2_service.api.location
  name     = google_cloud_run_v2_service.api.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloud_run_v2_service_iam_member" "ui_public" {
  count    = var.allow_unauthenticated ? 1 : 0
  project  = var.gcp_project_id
  location = google_cloud_run_v2_service.ui.location
  name     = google_cloud_run_v2_service.ui.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloud_run_v2_service_iam_member" "gateway_public" {
  count    = var.allow_unauthenticated ? 1 : 0
  project  = var.gcp_project_id
  location = google_cloud_run_v2_service.gateway.location
  name     = google_cloud_run_v2_service.gateway.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

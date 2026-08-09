# ─── 1. Enterprise Control Plane Dashboard API & Database ─────────────────────
# Multi-container Cloud Run revision housing the REST API and PostgreSQL sidecar.

resource "google_cloud_run_v2_service" "api" {
  name     = "${local.name_prefix}-api"
  location = var.gcp_region
  ingress  = "INGRESS_TRAFFIC_ALL"

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
      name       = "dashboard-api"
      image      = var.control_plane_api_image
      depends_on = ["postgres"]

      ports {
        container_port = 8400
      }

      resources {
        limits = {
          cpu    = var.api_cpu
          memory = var.api_memory
        }
        cpu_idle          = true
        startup_cpu_boost = true
      }

      env {
        name  = "DATABASE_URL"
        value = "postgres://${var.postgres_user}:${local.postgres_password}@127.0.0.1:5432/${var.postgres_db}?sslmode=disable"
      }
      env {
        name  = "DASHBOARD_PORT"
        value = "8400"
      }
      env {
        name  = "DEV_MODE"
        value = "true"
      }
      env {
        name  = "ALLOW_DEV_MODE"
        value = "true"
      }
      env {
        name  = "GATEWAY_SECRET"
        value = local.gateway_secret
      }
      env {
        name  = "POLICY_READ_SECRET"
        value = local.policy_read_secret
      }
      env {
        name  = "GATEWAY_URL"
        value = "https://${local.name_prefix}-gateway-${random_string.suffix.result}.${var.gcp_region}.run.app"
      }
      env {
        name  = "PROVIDER_KEY_ENCRYPTION_SECRET"
        value = local.encryption_secret
      }

      startup_probe {
        http_get {
          path = "/healthz"
          port = 8400
        }
        initial_delay_seconds = 5
        period_seconds        = 5
        failure_threshold     = 12
        timeout_seconds       = 3
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
        cpu_idle          = true
        startup_cpu_boost = true
      }

      env {
        name  = "POSTGRES_USER"
        value = var.postgres_user
      }
      env {
        name  = "POSTGRES_PASSWORD"
        value = local.postgres_password
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
        failure_threshold     = 10
        timeout_seconds       = 3
      }

      liveness_probe {
        tcp_socket {
          port = 5432
        }
        period_seconds    = 15
        failure_threshold = 3
        timeout_seconds   = 3
      }
    }
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }

  depends_on = [google_project_service.run]
}

# ─── 2. Enterprise Control Plane Frontend UI ──────────────────────────────────
# Web portal for SOC teams, policy administration, and telemetry dashboards.

resource "google_cloud_run_v2_service" "ui" {
  name     = "${local.name_prefix}-ui"
  location = var.gcp_region
  ingress  = "INGRESS_TRAFFIC_ALL"

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
        name  = "DASHBOARD_API_URL"
        value = google_cloud_run_v2_service.api.uri
      }

      startup_probe {
        http_get {
          path = "/"
          port = 80
        }
        initial_delay_seconds = 2
        period_seconds        = 5
        failure_threshold     = 6
        timeout_seconds       = 3
      }

      liveness_probe {
        http_get {
          path = "/"
          port = 80
        }
        period_seconds    = 15
        failure_threshold = 3
        timeout_seconds   = 3
      }
    }
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }

  depends_on = [
    google_project_service.run,
    google_cloud_run_v2_service.api
  ]
}

# ─── 3. AgentWall Gateway Proxy (Core Enforcement Engine) ─────────────────────
# High-performance Rust reverse proxy intercepting & policy-checking MCP calls.

resource "google_cloud_run_v2_service" "gateway" {
  name     = "${local.name_prefix}-gateway"
  location = var.gcp_region
  ingress  = "INGRESS_TRAFFIC_ALL"

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
        cpu_idle          = true
        startup_cpu_boost = true
      }

      env {
        name  = "AGENTWALL_LISTEN"
        value = "0.0.0.0:8080"
      }
      env {
        name  = "DASHBOARD_API_URL"
        value = google_cloud_run_v2_service.api.uri
      }
      env {
        name  = "POLICY_READ_SECRET"
        value = local.policy_read_secret
      }
      env {
        name  = "GATEWAY_SECRET"
        value = local.gateway_secret
      }
      env {
        name  = "POLICY_POLL_INTERVAL_SECS"
        value = "30"
      }
      env {
        name  = "AGENTWALL_LOG_PATH"
        value = "/var/log/agentwall/audit.log"
      }

      startup_probe {
        http_get {
          path = "/healthz"
          port = 8080
        }
        initial_delay_seconds = 2
        period_seconds        = 5
        failure_threshold     = 6
        timeout_seconds       = 3
      }

      liveness_probe {
        http_get {
          path = "/healthz"
          port = 8080
        }
        period_seconds    = 15
        failure_threshold = 3
        timeout_seconds   = 3
      }
    }
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }

  depends_on = [
    google_project_service.run,
    google_cloud_run_v2_service.api
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

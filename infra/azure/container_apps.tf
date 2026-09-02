# ─── 1. Control Plane Database (PostgreSQL) ───────────────────────────────────
# Internal service accessible only within the Azure Container Apps Environment.

resource "azurerm_container_app" "db" {
  name                         = "agentwall-db"
  container_app_environment_id = azurerm_container_app_environment.aca_env.id
  resource_group_name          = azurerm_resource_group.rg.name
  revision_mode                = "Single"
  tags                         = local.default_tags

  secret {
    name  = "postgres-password"
    value = local.postgres_password
  }

  template {
    min_replicas = var.min_replicas
    max_replicas = 1

    container {
      name   = "postgres"
      image  = var.control_plane_db_image
      cpu    = var.db_cpu
      memory = var.db_memory

      env {
        name  = "POSTGRES_USER"
        value = var.postgres_user
      }
      env {
        name        = "POSTGRES_PASSWORD"
        secret_name = "postgres-password"
      }
      env {
        name  = "POSTGRES_DB"
        value = var.postgres_db
      }

      startup_probe {
        transport               = "TCP"
        port                    = 5432
        interval_seconds        = 5
        timeout                 = 5
        failure_count_threshold = 12
      }

      readiness_probe {
        transport               = "TCP"
        port                    = 5432
        interval_seconds        = 10
        timeout                 = 5
        failure_count_threshold = 3
      }

      liveness_probe {
        transport               = "TCP"
        port                    = 5432
        interval_seconds        = 15
        timeout                 = 5
        failure_count_threshold = 3
      }
    }
  }

  ingress {
    external_enabled = false
    target_port      = 5432
    transport        = "tcp"

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }
}

# ─── 1b. Valkey Distributed Cache & Rate Limiting Engine ────────────────────────
resource "azurerm_container_app" "valkey" {
  name                         = "agentwall-valkey"
  container_app_environment_id = azurerm_container_app_environment.aca_env.id
  resource_group_name          = azurerm_resource_group.rg.name
  revision_mode                = "Single"
  tags                         = local.default_tags

  template {
    min_replicas = var.min_replicas
    max_replicas = 1

    container {
      name   = "valkey"
      image  = "valkey/valkey:7.2-alpine"
      cpu    = 0.25
      memory = "0.5Gi"

      startup_probe {
        transport               = "TCP"
        port                    = 6379
        interval_seconds        = 5
        timeout                 = 3
        failure_count_threshold = 6
      }
    }
  }

  ingress {
    external_enabled = false
    target_port      = 6379
    transport        = "tcp"

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }
}

# ─── 2. Enterprise Control Plane Dashboard API ────────────────────────────────
# Exposes the management REST API and policy distribution endpoint.

resource "azurerm_container_app" "api" {
  name                         = "agentwall-api"
  container_app_environment_id = azurerm_container_app_environment.aca_env.id
  resource_group_name          = azurerm_resource_group.rg.name
  revision_mode                = "Single"
  tags                         = local.default_tags

  secret {
    name  = "database-url"
    value = "postgres://${var.postgres_user}:${local.postgres_password}@agentwall-db:5432/${var.postgres_db}?sslmode=disable"
  }
  secret {
    name  = "gateway-secret"
    value = local.gateway_secret
  }
  secret {
    name  = "policy-read-secret"
    value = local.policy_read_secret
  }
  secret {
    name  = "encryption-secret"
    value = local.encryption_secret
  }
  secret {
    name  = "session-secret"
    value = local.session_secret
  }

  template {
    min_replicas = var.min_replicas
    max_replicas = var.max_replicas

    container {
      name   = "dashboard-api"
      image  = var.control_plane_api_image
      cpu    = var.api_cpu
      memory = var.api_memory

      env {
        name        = "DATABASE_URL"
        secret_name = "database-url"
      }
      env {
        name  = "VALKEY_URL"
        value = "agentwall-valkey:6379"
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
        name        = "GATEWAY_SECRET"
        secret_name = "gateway-secret"
      }
      env {
        name        = "POLICY_READ_SECRET"
        secret_name = "policy-read-secret"
      }
      env {
        name  = "GATEWAY_URL"
        value = "http://agentwall-gateway:8080"
      }
      env {
        name        = "PROVIDER_KEY_ENCRYPTION_SECRET"
        secret_name = "encryption-secret"
      }
      env {
        name        = "AGENTWALL_SESSION_SECRET"
        secret_name = "session-secret"
      }
      env {
        name        = "AGENTCONTROL_SESSION_SECRET"
        secret_name = "session-secret"
      }
      # Required by Go config.Load() in production: tells the API it runs behind
      # a TLS-terminating ingress (ACA) so INGRESS_AUTH_SECRET is not enforced.
      env {
        name  = "DIRECT_TLS_ENABLED"
        value = "true"
      }
      env {
        name        = "INGRESS_AUTH_SECRET"
        secret_name = "gateway-secret"
      }

      readiness_probe {
        transport               = "HTTP"
        port                    = 8400
        path                    = "/healthz"
        interval_seconds        = 10
        timeout                 = 3
        failure_count_threshold = 3
      }

      liveness_probe {
        transport               = "HTTP"
        port                    = 8400
        path                    = "/healthz"
        interval_seconds        = 15
        timeout                 = 5
        failure_count_threshold = 3
      }
    }
  }

  ingress {
    external_enabled = true
    target_port      = 8400
    transport        = "auto"

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  depends_on = [azurerm_container_app.db]
}

# ─── 3. Enterprise Control Plane Frontend UI ──────────────────────────────────
# Web portal for SOC teams, policy management, and telemetry dashboards.

resource "azurerm_container_app" "ui" {
  name                         = "agentwall-ui"
  container_app_environment_id = azurerm_container_app_environment.aca_env.id
  resource_group_name          = azurerm_resource_group.rg.name
  revision_mode                = "Single"
  tags                         = local.default_tags

  template {
    min_replicas = var.min_replicas
    max_replicas = var.max_replicas

    container {
      name   = "control-plane-ui"
      image  = var.control_plane_ui_image
      cpu    = var.ui_cpu
      memory = var.ui_memory

      env {
        name  = "DASHBOARD_API_URL"
        value = "https://${azurerm_container_app.api.ingress[0].fqdn}"
      }

      readiness_probe {
        transport               = "HTTP"
        port                    = 80
        path                    = "/"
        interval_seconds        = 15
        timeout                 = 5
        failure_count_threshold = 3
      }

      liveness_probe {
        transport               = "HTTP"
        port                    = 80
        path                    = "/"
        interval_seconds        = 20
        timeout                 = 5
        failure_count_threshold = 3
      }
    }
  }

  ingress {
    external_enabled = true
    target_port      = 80
    transport        = "auto"

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  depends_on = [azurerm_container_app.api]
}

# ─── 4. AgentWall Gateway Proxy (Core Enforcement Engine) ─────────────────────
# High-performance Rust reverse proxy intercepting & policy-checking MCP calls.

resource "azurerm_container_app" "gateway" {
  name                         = "agentwall-gateway"
  container_app_environment_id = azurerm_container_app_environment.aca_env.id
  resource_group_name          = azurerm_resource_group.rg.name
  revision_mode                = "Single"
  tags                         = local.default_tags

  secret {
    name  = "policy-read-secret"
    value = local.policy_read_secret
  }
  secret {
    name  = "gateway-secret"
    value = local.gateway_secret
  }

  template {
    min_replicas = var.min_replicas
    max_replicas = var.max_replicas

    container {
      name   = "gateway"
      image  = var.container_image
      cpu    = var.gateway_cpu
      memory = var.gateway_memory

      # AGENTCONTROL_LISTEN must be set — the Rust binary reads this env var first.
      # Without it, the default is 127.0.0.1:8080 (loopback), which triggers a
      # fatal security error when binding 0.0.0.0 without identity auth.
      env {
        name  = "AGENTCONTROL_LISTEN"
        value = "0.0.0.0:8080"
      }
      env {
        name  = "AGENTWALL_LISTEN"
        value = "0.0.0.0:8080"
      }
      # AGENTCONTROL_CENTRALIZED=true + AGENTCONTROL_ADMIN_TOKEN are REQUIRED to
      # pass the non-loopback bind security guard in src/main.rs.
      env {
        name  = "AGENTCONTROL_CENTRALIZED"
        value = "true"
      }
      env {
        name        = "AGENTCONTROL_ADMIN_TOKEN"
        secret_name = "gateway-secret"
      }
      env {
        name  = "AGENTCONTROL_POLICY_PATH"
        value = "/app/policy.example.yaml"
      }
      env {
        name  = "AGENTCONTROL_HUB_URL"
        value = "https://${azurerm_container_app.api.ingress[0].fqdn}"
      }
      env {
        name  = "DASHBOARD_API_URL"
        value = "https://${azurerm_container_app.api.ingress[0].fqdn}"
      }
      env {
        name        = "POLICY_READ_SECRET"
        secret_name = "policy-read-secret"
      }
      env {
        name        = "GATEWAY_SECRET"
        secret_name = "gateway-secret"
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

      readiness_probe {
        transport               = "HTTP"
        port                    = 8080
        path                    = "/healthz"
        interval_seconds        = 10
        timeout                 = 3
        failure_count_threshold = 3
      }

      liveness_probe {
        transport               = "HTTP"
        port                    = 8080
        path                    = "/healthz"
        interval_seconds        = 15
        timeout                 = 5
        failure_count_threshold = 3
      }
    }
  }

  ingress {
    external_enabled = true
    target_port      = 8080
    transport        = "auto"

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  depends_on = [azurerm_container_app.api]
}

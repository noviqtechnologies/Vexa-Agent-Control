# ─── Public Service Endpoints (with Free Managed HTTPS / TLS) ────────────────

output "gateway_url" {
  description = "Public HTTPS endpoint for the AgentWall Gateway proxy."
  value       = "https://${azurerm_container_app.gateway.ingress[0].fqdn}"
}

output "control_plane_ui_url" {
  description = "Public HTTPS endpoint for the AgentWall Enterprise Control Plane UI."
  value       = "https://${azurerm_container_app.ui.ingress[0].fqdn}"
}

output "dashboard_api_url" {
  description = "Public HTTPS endpoint for the Control Plane Dashboard API."
  value       = "https://${azurerm_container_app.api.ingress[0].fqdn}"
}

output "health_check_url" {
  description = "Direct health check URL for the AgentWall Gateway."
  value       = "https://${azurerm_container_app.gateway.ingress[0].fqdn}/healthz"
}

# ─── Resource & Environment Identifiers ───────────────────────────────────────

output "resource_group_name" {
  description = "Name of the provisioned Azure Resource Group."
  value       = azurerm_resource_group.rg.name
}

output "container_app_environment_name" {
  description = "Name of the Azure Container Apps Environment."
  value       = azurerm_container_app_environment.aca_env.name
}

output "log_analytics_workspace_name" {
  description = "Name of the Log Analytics Workspace capturing container logs."
  value       = azurerm_log_analytics_workspace.logs.name
}

output "acr_login_server" {
  description = "Azure Container Registry login server (when acr_enabled = true)."
  value       = var.acr_enabled ? azurerm_container_registry.acr[0].login_server : "disabled"
}

# ─── Cross-Platform Verification & Diagnostic Helpers ─────────────────────────

output "quick_verify_command" {
  description = "Universal curl command to verify gateway health across Windows, Linux, and macOS."
  value       = "curl -i https://${azurerm_container_app.gateway.ingress[0].fqdn}/healthz"
}

output "view_gateway_logs_command" {
  description = "Azure CLI command to stream live logs from the AgentWall Gateway container."
  value       = "az containerapp logs show --name agentwall-gateway --resource-group ${azurerm_resource_group.rg.name} --follow"
}

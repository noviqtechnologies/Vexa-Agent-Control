# ─── Public Service Endpoints (Free Auto-Issued HTTPS / TLS) ───────────────────

output "gateway_url" {
  description = "Public HTTPS endpoint for the AgentWall Gateway proxy."
  value       = "https://${azurerm_container_app.gateway.ingress[0].fqdn}"
}

output "control_plane_ui_url" {
  description = "Public HTTPS endpoint for the AgentWall Enterprise Control Plane UI."
  value       = "https://${azurerm_container_app.ui.ingress[0].fqdn}"
}

output "control_plane_url" {
  description = "Alias for control_plane_ui_url — matches AWS ECS output naming convention for cross-platform consistency."
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

output "azure_region" {
  description = "Azure region where resources are deployed."
  value       = azurerm_resource_group.rg.location
}

output "environment" {
  description = "Deployment environment name."
  value       = var.environment
}

output "aca_environment_name" {
  description = "Name of the Azure Container Apps managed environment."
  value       = azurerm_container_app_environment.aca_env.name
}

output "acr_login_server" {
  description = "Login server for the Azure Container Registry (when acr_enabled = true)."
  value       = var.acr_enabled ? azurerm_container_registry.acr[0].login_server : "disabled"
}

# ─── Cross-Platform Verification & Diagnostic Helpers ─────────────────────────

output "quick_verify_command" {
  description = "Universal curl command to verify gateway health across Windows, Linux, and macOS."
  value       = "curl -i https://${azurerm_container_app.gateway.ingress[0].fqdn}/healthz"
}

output "view_gateway_logs_command" {
  description = "Azure CLI command to stream live logs from the AgentWall Gateway container app."
  value       = "az containerapp logs show --name ${azurerm_container_app.gateway.name} --resource-group ${azurerm_resource_group.rg.name} --follow"
}

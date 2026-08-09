# ─── AgentWallPolicy Custom Resource ─────────────────────────────────────────
#
# Temporarily commented out during teardown to avoid CRD schema validation check.

# resource "kubernetes_manifest" "agentwall_policy" {
#   manifest = {
#     apiVersion = "agentwall.io/v1alpha1"
#     kind       = "AgentWallPolicy"
#     metadata = {
#       name      = "aws-production-policy"
#       namespace = var.agentwall_namespace
#     }
#     spec = {
#       policy = <<-POLICY
#         version: "2.0"
#         default_action: deny
#         tools:
#           - name: "read_file"
#             action: allow
#           - name: "exec_shell"
#             action: block
#         firewall:
#           enabled: true
#           cycle_detection:
#             max_attempts: 3
#             action: pivot_error
#       POLICY
# 
#       networkPolicy = {
#         enforced = true
#         mcpPort  = 8080
#         agentPodSelector = {
#           "agentwall.io/agent" = "true"
#         }
#         gatewayPodSelector = {
#           "agentwall.io/gateway" = "true"
#         }
#       }
#     }
#   }
# 
#   depends_on = [helm_release.agentwall]
# }

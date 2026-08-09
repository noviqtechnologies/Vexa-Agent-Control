variable "cluster_endpoint" {
  type = string
}
variable "cluster_certificate_authority_data" {
  type = string
}
variable "cluster_name" {
  type = string
}

output "cluster_endpoint" {
  value = var.cluster_endpoint
}
output "cluster_certificate_authority_data" {
  value = var.cluster_certificate_authority_data
}
output "cluster_name" {
  value = var.cluster_name
}

# =============================================================================
# SVT System — Terraform Outputs
# =============================================================================

output "gke_cluster_endpoint" {
  description = "GKE cluster endpoint"
  value       = google_container_cluster.svt_cluster.endpoint
  sensitive   = true
}

output "gke_cluster_name" {
  description = "GKE cluster name"
  value       = google_container_cluster.svt_cluster.name
}

output "db_connection_name" {
  description = "Cloud SQL instance connection name"
  value       = google_sql_database_instance.svt_postgres.connection_name
}

output "db_private_ip" {
  description = "Cloud SQL private IP address"
  value       = google_sql_database_instance.svt_postgres.private_ip_address
  sensitive   = true
}

output "redis_host" {
  description = "Memorystore Redis host"
  value       = google_redis_instance.svt_redis.host
  sensitive   = true
}

output "redis_port" {
  description = "Memorystore Redis port"
  value       = google_redis_instance.svt_redis.port
}

output "redis_auth_string" {
  description = "Memorystore Redis auth string"
  value       = google_redis_instance.svt_redis.auth_string
  sensitive   = true
}

output "kms_key_name" {
  description = "KMS crypto key resource name"
  value       = google_kms_crypto_key.svt_issuer_keys.id
}

output "backup_bucket" {
  description = "GCS backup bucket name"
  value       = google_storage_bucket.svt_backups.name
}

output "backend_service_account_email" {
  description = "Backend service account email"
  value       = google_service_account.svt_backend_sa.email
}

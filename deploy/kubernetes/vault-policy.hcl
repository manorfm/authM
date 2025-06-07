path "user-manager-service/data/config" {
  capabilities = ["read"]
}

path "user-manager-service/data/*" {
  capabilities = ["read"]
} 
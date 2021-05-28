plugin "nspawn" {
  config {
    enabled = true
  }
}
server {
  default_scheduler_config {
    memory_oversubscription_enabled = true
  }
}

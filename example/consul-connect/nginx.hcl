job "consul-connect" {
  datacenters = ["dc1"]
  type = "service"
  group "bridge" {
    count = 1
    task "nginx" {
      driver = "nspawn"
      config {
        image = "example/consul-connect/image"
        resolv_conf = "copy-host"
        command = ["/bin/bash", "-c", "dhclient && nginx && tail -f /var/log/nginx/access.log " ]
        boot = false
        process_two = true
      }
    }
    network {
      mode = "bridge"
    }
    service {
      tags = ["nginx", "connect"]
      port = "80"

      connect {
        sidecar_service {}
      }
    }
  }
}

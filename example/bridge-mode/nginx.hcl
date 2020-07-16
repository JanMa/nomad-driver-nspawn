job "bridge-mode" {
  datacenters = ["dc1"]
  type = "service"
  group "bridge" {
    count = 1
    task "nginx" {
      driver = "nspawn"
      config {
        image = "example/bridge-mode/image"
        resolv_conf = "copy-host"
        command = ["/bin/bash", "-c", "dhclient && nginx && tail -f /var/log/nginx/access.log " ]
        boot = false
        process_two = true
      }
    }
    network {
      port "http" {
        static = 8081
        to = 80
      }
      mode = "bridge"
    }
    service {
      tags = ["nginx"]
      port = "http"
      address_mode = "host"

      check {
        type = "http"
        port = "http"
        path = "/"
        interval = "10s"
        timeout = "5s"
        address_mode = "driver"
      }
    }
  }
}

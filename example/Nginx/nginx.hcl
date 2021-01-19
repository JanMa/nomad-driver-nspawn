job "nginx" {
  datacenters = ["dc1"]
  type = "service"
  group "linux" {
    count = 1
    network {
      port "http" {
        static = "8080"
        to = "80"
      }
    }
    task "nginx" {
      driver = "nspawn"
      config {
        image = "example/Nginx/image"
        resolv_conf = "copy-host"
        command = ["/bin/bash", "-c", "dhclient && nginx && tail -f /var/log/nginx/access.log " ]
        boot = false
        process_two = true
        ports = ["http"]
      }
    }
  }
}

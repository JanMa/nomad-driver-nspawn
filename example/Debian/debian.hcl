job "debian" {
  datacenters = ["dc1"]
  type = "service"
  group "linux" {
    count = 1
    task "debian" {
      driver = "nspawn"
      config {
        image = "example/Debian/image"
        resolv_conf = "copy-host"
      }
    }
  }
}

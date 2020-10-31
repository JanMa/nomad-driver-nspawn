job "system-job" {
  datacenters = ["dc1"]
  type = "system"
  group "linux" {
    count = 1
    task "debian" {
      driver = "nspawn"
      config {
        image = "debian-buster"
        image_download {
          url = "https://nspawn.org/storage/debian/buster/tar/image.tar.xz"
        }
        network_veth = false
        user_namespacing = false
      }
    }
  }
}

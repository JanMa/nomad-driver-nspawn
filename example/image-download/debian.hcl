job "image-download" {
  datacenters = ["dc1"]
  type = "service"
  group "linux" {
    count = 1
    task "debian" {
      driver = "nspawn"
      config {
        image = "debian-buster"
        resolv_conf = "copy-host"
        image_download {
          url = "https://nspawn.org/storage/debian/buster/tar/image.tar.xz"
        }
      }
    }
  }
}

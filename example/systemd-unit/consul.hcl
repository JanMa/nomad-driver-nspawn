job "consul" {
  datacenters = ["dc1"]
  type = "service"
  group "linux" {
    count = 1

    task "consul" {
      driver = "nspawn"
      config {
        image = "consul"
        image_download {
          url = "https://cloud.debian.org/images/cloud/buster/20201214-484/debian-10-generic-amd64-20201214-484.qcow2"
          force = true
          type = "raw"
        }
        environment = {
          SYSTEMD_UNIT_PATH = "${NOMAD_TASK_DIR}/systemd:"
        }
      }

      artifact {
        source = "https://releases.hashicorp.com/consul/1.9.0/consul_1.9.0_linux_amd64.zip"
        destination = "local/consul"
      }

      template {
        data = <<EOH
[Unit]
Description="HashiCorp Consul - A service mesh solution"
Documentation=https://www.consul.io/
Requires=network-online.target
After=network-online.target

[Service]
ExecStart=[[ env "NOMAD_TASK_DIR" ]]/consul/consul agent -dev -bind '{{ GetInterfaceIP "host0" }}' -client '{{ GetInterfaceIP "host0" }}'
ExecReload=/bin/kill --signal HUP $MAINPID
KillMode=process
KillSignal=SIGTERM
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOH
        destination = "local/systemd/consul.service"
        left_delimiter = "[["
        right_delimiter = "]]"
      }

      template {
        data = <<EOH
[Unit]
Wants=systemd-networkd.service systemd-resolved.service consul.service
EOH
        destination = "local/systemd/multi-user.target.d/wants.conf"
      }
    }
  }
}

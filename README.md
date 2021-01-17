# Nomad Systemd-Nspawn driver

This is a task driver for Hashicorp [Nomad](https://nomadproject.io) to run
containers with `systemd-nspawn`.

Containers started via this driver will have private networking enabled by
default and their machine ID will be set to the allocation ID of the started
Nomad task.

## Client requirements

* [Nomad](https://nomadproject.io) 1.0.2+ running as `root`
* [Go](https://golang.org/doc/install) 1.15
* Linux
* [`systemd-nspawn`](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html)
  installed

## Building the driver from source

Checkout this repository and simply run `make`.

```shell
$ git clone https://github.com/JanMa/nomad-driver-nspawn.git
$ cd nomad-driver-nspawn
$ make
```

## Testing the driver

To execute the built-in test suite run

``` shell
$ make test
```

## Using the driver

To test the driver, run the Nomad agent in development mode with the following
command

```shell
$ sudo nomad agent -dev -plugin-dir=$(pwd) -config=example/config.hcl
```

## Minimal job example

```hcl
    task "debian" {
      driver = "nspawn"
      config {
        image = "example/Debian/image"
        resolv_conf = "copy-host"
      }
    }
```

## Argument reference

The driver supports the following subset of possible arguments from `systemd-nspawn`, which
should cover a broad range of use cases:

* [`boot`](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html#-b) -
  (Optional) `true` (default) or `false`. Search for an init program and invoke
  it as PID 1. Arguments specified in `command` will be used as arguments for
  the init program.
* [`ephemeral`](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html#-x) -
  (Optional) `true` or `false` (default). Make an ephemeral copy of the image
  before staring the container.
* [`process_two`](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html#-a) -
  (Optional) `true` or `false` (default). Start the command specified with
  `command` as PID 2, using a minimal stub init as PID 1.
* [`read_only`](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html#--read-only) -
  (Optional) `true` or `false` (default). Mount the used image as read only.
* [`user_namespacing`](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html#-U) -
  (Optional) `true` (default) or `false`. Enable user namespacing features
  inside the container.
* `command` - (Optional) A list of strings to pass as the used command to the
  container.

  ```hcl
  config {
    command = [ "/bin/bash", "-c", "dhclient && nginx && tail -f /var/log/nginx/access.log" ]
  }
  ```
* [`console`](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html#--console=MODE) -
  (Optional) Configures how to set up standard input, output and error output
  for the container.
* `image` - The image to be used in the container. This can either be the path
  to a
  [directory](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html#-D),
  the path to a file system
  [image](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html#-i)
  or block device or the name of an image registered with
  [`systemd-machined`](https://www.freedesktop.org/software/systemd/man/systemd-machined.service.html).
  A path can be specified as a relative path from the configured Nomad plugin
  directory. **This option is mandatory**.
* `image_download` - (Optional) Download the used image according to the
  settings defined in this block. Structure is documented below.
* [`pivot_root`](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html#--pivot-root=) -
  (Optional) Pivot the specified directory to be the containers root directory.
* [`resolv_conf`](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html#--resolv-conf=) -
  (Optional) Configure how `/etc/resolv.conf` is handled inside the container.
* [`user`](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html#-u) -
  (Optional) Change to the specified user in the container's user database.
* [`volatile`](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html#--volatile) -
  (Optional) Boot the container in volatile mode.
* [`working_directory`](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html#--chdir=) -
  (Optional) Set the working directory inside the container.
* [`bind`](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html#--bind=) -
  (Optional) Files or directories to bind mount inside the container.

  ```hcl
  config {
    bind {
      "/var/lib/postgresql" = "/postgres"
    }
  }
  ```
* [`bind_read_only`](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html#--bind=) -
  (Optional) Files or directories to bind mount read only inside the container.

  ```hcl
  config {
    bind_read_only {
      "/etc/passwd" = "/etc/passwd"
    }
  }

  ```
* `environment` - (Optional) Environment variables to pass to the init process
  in the container.

  ```hcl
  config {
    environment = {
      FOO = "bar"
    }
  }
  ```
* `port_map` - (Optional) A key-value map of port labels. Works the same way as
  in the [docker
  driver](https://www.nomadproject.io/docs/drivers/docker.html#using-the-port-map).
  **Note:** `systemd-nspawn` will not expose ports to the loopback interface of
  your host.

  ```hcl
  config {
    port_map {
      http = 80
    }
  }
  ```
* [`capability`](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html#--capability=) -
  (Optional) List of additional capabilities to grant the container.

  ```hcl
  config {
    capability = ["CAP_NET_ADMIN"]
  }
  ```
* [`network_veth`](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html#-n) -
  (Optional) `true` (default) or `false`. Create a virtual ethernet link between
  the host and the container.
* [`network_zone`](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html#--network-zone=) -
  (Optional) Start the container in the given network zone. Each container may
  only be part of one zone, but each zone may contain any number of containers.

The `image_download` block supports the following arguments:
* `url` - The URL of the image to download. The URL must be of type `http://` or
  `https://`. **This option is mandatory**.
* [`verify`](https://www.freedesktop.org/software/systemd/man/machinectl.html#pull-tar%20URL%20%5BNAME%5D) -
  (Optional) `no` (default), `signature` or `checksum`. Whether to verify the
  image before making it available.
* `force` - (Optional) `true` or `false` (default) If a local copy already
  exists, delete it first and replace it by the newly downloaded image.
* `type` - (Optional) `tar` (default) or `raw`. The type of image to download.

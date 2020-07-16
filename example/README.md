# Examples

This folder contains a few simple examples for the driver.

## `config.hcl`

A minimal config file for the Nomad agent to enable the driver.

## Debian

This folder contains a very simple job file which boots a plain Debian
container. To run the job, you first need to build an image to be used in the
container. Install [`mkosi`](https://github.com/systemd/mkosi) on your host and
run the following command from inside the `Debian` folder:

```shell
$ sudo mkosi
```

This will create a minimal Debian image in side the `image` subfolder which will
be used by the `debian.hcl` job file. Start the Nomad agent in development mode
as shown in the repo's [README.md](../README.md). Then execute

```shell
$ nomad run debian.hcl
```

to run the job.

## Nginx

This folder contains a simple job file to start a container with a Bash script
running as process two. The script will setup DHCP and then start Nginx. The
containers port `80` will be forwarded to port `8080` on the host. To run the
job, build the image as described above, start Nomad in development mode and
then run:

```shell
$ nomad run nginx.hcl
```

## image-download

This folder contains basically the same job file as the `Debian` folder but
downloads the used image from [nspawn.org](https://nspawn.org). To run the job,
simply execute:

```shell
$ nomad run debian.hcl
```

## bridge-mode

This folder contains the same job as the `Nginx` folder but configured to run in
`bridge` network mode. Make sure to have a look at the [Nomad Consul Connect
example](https://www.nomadproject.io/docs/integrations/consul-connect#prerequisites)
and install all necessary prerequisites before running this job.

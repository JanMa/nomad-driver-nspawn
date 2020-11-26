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

## consul-connect

This folder contains yet another variant of the `Nginx` job. This time, bridge
mode is enabled and a `consul-connect` sidecar proxy is registered for the
service. To run this job, make sure you followed the tutorial linked above. Then
start Nomad with Consul connect enabled.

```shell
$ sudo nomad agent -dev-connect
```

Open another terminal window and also start Consul

```shell
$ sudo consul -agent -dev
```

In a third terminal window you can now start the Nomad job via 

```shell
$ nomad run nginx.hcl
```

If you want to connect to the service, you will need to start a local Consul
connect proxy.

```shell
$ consul connect proxy -upstream 'consul-connect-bridge:8082' -service proxy
```

Then you can access the service in a fourth terminal window by connecting to the
proxy.

```shell
$ curl http://127.0.0.1:8082
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
```

## system-job

This folder contains the same job as the `image-download` folder, but starts it
as a Nomad system job and without private networking enabled. Any ports exposed
in the container will be directly accessible on the host.

## network-zone

This folder contains two job files which each start a job with two tasks running
Debian. All started allocations will be part of the same network zone.

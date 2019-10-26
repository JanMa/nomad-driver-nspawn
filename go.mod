module github.com/JanMa/nomad-driver-nspawn

go 1.13

require (
	github.com/LK4D4/joincontext v0.0.0-20171026170139-1724345da6d5 // indirect
	github.com/StackExchange/wmi v0.0.0-20190523213315-cbe66965904d // indirect
	github.com/containerd/cgroups v0.0.0-20191011165608-5fbad35c2a7e
	github.com/coreos/go-systemd v0.0.0-20190719114852-fd7a80b32e1f
	github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f // indirect
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/gorhill/cronexpr v0.0.0-20180427100037-88b0669f7d75 // indirect
	github.com/hashicorp/consul/api v1.2.0 // indirect
	github.com/hashicorp/go-hclog v0.9.2
	github.com/hashicorp/go-immutable-radix v1.1.0 // indirect
	github.com/hashicorp/go-plugin v1.0.1 // indirect
	github.com/hashicorp/go-version v1.2.0 // indirect
	github.com/hashicorp/golang-lru v0.5.3 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/hashicorp/nomad v0.10.0
	github.com/hashicorp/raft v1.1.1 // indirect
	github.com/hpcloud/tail v1.0.0 // indirect
	github.com/mitchellh/copystructure v1.0.0 // indirect
	github.com/mitchellh/hashstructure v1.0.0 // indirect
	github.com/opencontainers/runc v1.0.0-rc6.0.20190125192819-8011af4a96d6 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/shirou/gopsutil v2.19.9+incompatible // indirect
	github.com/shirou/w32 v0.0.0-20160930032740-bb4de0191aa4 // indirect
	github.com/ugorji/go v1.1.7 // indirect
	github.com/zclconf/go-cty v1.1.0 // indirect
	golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550 // indirect
	golang.org/x/net v0.0.0-20191021144547-ec77196f6094 // indirect
	golang.org/x/sys v0.0.0-20191026070338-33540a1f6037 // indirect
	google.golang.org/grpc v1.24.0 // indirect
	gopkg.in/fsnotify.v1 v1.4.7 // indirect
	gopkg.in/lxc/go-lxc.v2 v2.0.0-20181227225324-7c910f8a5edc // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
)

replace (
	github.com/hashicorp/go-msgpack/codec v0.5.5 => github.com/ugorji/go/codec v1.1.7
	github.com/shirou/gopsutil v2.19.9+incompatible => github.com/hashicorp/gopsutil v2.17.13-0.20190117153606-62d5761ddb7d+incompatible
	github.com/ugorji/go v1.1.7 => github.com/hashicorp/go-msgpack v0.0.0-20190927123313-23165f7bc3c2
)

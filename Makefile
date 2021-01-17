VERSION := $(shell git describe --dirty --tags --no-contains)
BINARY := nomad-driver-nspawn
PWD := $(shell pwd)
GOPATH := $(shell go env GOPATH)
GO115 := $(GOPATH)/bin/go1.15
GO115_INSTALLED := $(shell $GO115 version 2> /dev/null)
BUILDARGS := build -mod=vendor -a -v -ldflags '-extldflags "-static" -X github.com/JanMa/nomad-driver-nspawn/nspawn.pluginVersion=${VERSION}' -o $(BINARY)

.PHONY: docker-image get tidy vendor test cover clean

build: $(BINARY)

docker-build: docker-image
		sudo docker run --rm -e GO111MODULE=on -e CGO_ENABLED=0 -e GOOS=linux \
			-v "${PWD}":/usr/src/nomad-driver-nspawn -w /usr/src/nomad-driver-nspawn golang:1.15-alpine \
			go $(BUILDARGS)

$(BINARY): *.go nspawn/*.go | .go115
		GO111MODULE=on CGO_ENABLED=0 GOOS=linux $(GO115) $(BUILDARGS)

*.go:

nspawn/*.go:


docker-image:
		sudo docker pull golang:1.15-alpine

get:
		GO111MODULE=on go get -v

tidy: get
		GO111MODULE=on go mod tidy -v

vendor:	tidy
		GO111MODULE=on go mod vendor -v

nspawn.test: | .go115
		go test -c ./nspawn

test: | nspawn.test
		sudo ./nspawn.test

nspawn.cover: | .go115
		go test -cover -c ./nspawn -o nspawn.cover

cover: | nspawn.cover
		sudo ./nspawn.cover

clean:
		@rm -rf nomad-driver-nspawn nspawn.test nspawn.cover

.ONESHELL:
.go115:
		@echo Installing Go 1.15
		cd $$HOME
		go get -v golang.org/dl/go1.15
		$(GO115) download
		cd $$OLDPWD
		touch .go115

all: test build

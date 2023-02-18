VERSION := $(shell git describe --dirty --tags --no-contains)
BINARY := nomad-driver-nspawn
PWD := $(shell pwd)
GOPATH := $(shell go env GOPATH)
GO120 := $(GOPATH)/bin/go1.20
GO120_INSTALLED := $(shell $GO120 version 2> /dev/null)
BUILDARGS := build -mod=vendor -a -v -ldflags '-extldflags "-static" -X github.com/JanMa/nomad-driver-nspawn/nspawn.pluginVersion=${VERSION}' -o $(BINARY)

.DELETE_ON_ERROR:
.PHONY: docker-image get tidy vendor test cover clean

build: $(BINARY)

docker-build: docker-image
		sudo docker run --rm -e GO111MODULE=on -e GOOS=linux \
			-v "${PWD}":/usr/src/nomad-driver-nspawn -w /usr/src/nomad-driver-nspawn golang:1.20-alpine \
			go $(BUILDARGS)

$(BINARY): *.go nspawn/*.go | .go120
		GO111MODULE=on GOOS=linux $(GO120) $(BUILDARGS)

*.go:

nspawn/*.go:


docker-image:
		sudo docker pull golang:1.20-alpine

get: | .go120
		GO111MODULE=on $(GO120) get -v

tidy: get | .go120
		GO111MODULE=on $(GO120) mod tidy -v

vendor:	tidy | .go120
		GO111MODULE=on $(GO120) mod vendor -v

nspawn.test: *.go nspawn/*.go | .go120
		$(GO120) test -c ./nspawn

test: nspawn.test
		sudo ./nspawn.test

nspawn.cover: *.go nspawn/*.go | .go120
		$(GO120) test -cover -c ./nspawn -o nspawn.cover

cover: nspawn.cover
		sudo ./nspawn.cover

clean:
		@rm -rf nomad-driver-nspawn nspawn.test nspawn.cover

.ONESHELL:
.go120:
		@echo Installing Go 1.20
		cd $$HOME
		go install -v golang.org/dl/go1.20@latest
		$(GO120) download
		cd $$OLDPWD
		touch .go120

all: test build

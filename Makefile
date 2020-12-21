VERSION := $(shell git describe --dirty --tags --no-contains)
BINARY := nomad-driver-nspawn
PWD := $(shell pwd)
GOPATH := $(shell go env GOPATH)
GO114 := $(GOPATH)/bin/go1.14
GO114_INSTALLED := $(shell $GO114 version 2> /dev/null)
BUILDARGS := build -mod=vendor -a -v -ldflags '-extldflags "-static" -X github.com/JanMa/nomad-driver-nspawn/nspawn.pluginVersion=${VERSION}' -o $(BINARY)

.PHONY: docker-image get tidy vendor test cover clean

build: $(BINARY)

docker-build: docker-image
		sudo docker run --rm -e GO111MODULE=on -e CGO_ENABLED=0 -e GOOS=linux \
			-v "${PWD}":/usr/src/nomad-driver-nspawn -w /usr/src/nomad-driver-nspawn golang:1.14-alpine \
			go $(BUILDARGS)

$(BINARY): *.go nspawn/*.go | .go114
		GO111MODULE=on CGO_ENABLED=0 GOOS=linux $(GO114) $(BUILDARGS)

*.go:

nspawn/*.go:


docker-image:
		sudo docker pull golang:1.14-alpine

get:
		GO111MODULE=on go get -v

tidy: get
		GO111MODULE=on go mod tidy -v

vendor:	tidy
		GO111MODULE=on go mod vendor -v

nspawn.test: | .go114
		go test -c ./nspawn

test: | nspawn.test
		sudo ./nspawn.test

nspawn.cover: | .go114
		go test -cover -c ./nspawn -o nspawn.cover

cover: | nspawn.cover
		sudo ./nspawn.cover

clean:
		@rm -rf nomad-driver-nspawn nspawn.test nspawn.cover

.ONESHELL:
.go114:
		@echo Installing Go 1.14
		cd $$HOME
		go get -v golang.org/dl/go1.14
		$(GO114) download
		cd $$OLDPWD
		touch .go114

all: test build

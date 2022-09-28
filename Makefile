VERSION := $(shell git describe --dirty --tags --no-contains)
BINARY := nomad-driver-nspawn
PWD := $(shell pwd)
GOPATH := $(shell go env GOPATH)
GO118 := $(GOPATH)/bin/go1.18
GO118_INSTALLED := $(shell $GO118 version 2> /dev/null)
BUILDARGS := build -mod=vendor -v -ldflags '-extldflags "-static" -X github.com/JanMa/nomad-driver-nspawn/nspawn.pluginVersion=${VERSION}' -o $(BINARY)

.PHONY: docker-image get tidy vendor test cover clean

build: $(BINARY)

docker-build: docker-image
		sudo docker run --rm -e GO111MODULE=on -e CGO_ENABLED=0 -e GOOS=linux \
			-v "${PWD}":/usr/src/nomad-driver-nspawn -w /usr/src/nomad-driver-nspawn golang:1.18-alpine \
			go $(BUILDARGS)

$(BINARY): *.go nspawn/*.go | .go118
		GO111MODULE=on CGO_ENABLED=0 GOOS=linux $(GO118) $(BUILDARGS)

*.go:

nspawn/*.go:


docker-image:
		sudo docker pull golang:1.18-alpine

get:
		GO111MODULE=on go get -v

tidy: get
		GO111MODULE=on go mod tidy -v

vendor:	tidy
		GO111MODULE=on go mod vendor -v

nspawn.test: *.go nspawn/*.go | .go118
		go test -c ./nspawn

test: nspawn.test
		sudo ./nspawn.test

nspawn.cover: *.go nspawn/*.go | .go118
		go test -cover -c ./nspawn -o nspawn.cover

cover: nspawn.cover
		sudo ./nspawn.cover

clean:
		@rm -rf nomad-driver-nspawn nspawn.test nspawn.cover

.ONESHELL:
.go118:
		@echo Installing Go 1.18
		cd $$HOME
		go install -v golang.org/dl/go1.18@latest
		$(GO118) download
		cd $$OLDPWD
		touch .go118

all: test build

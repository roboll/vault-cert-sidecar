TAG     := $(shell git describe --tags --always)
PKGS    := $(shell go list ./... | grep -v /vendor/)
PREFIX  := quay.io/roboll

generate:
	go generate ${PKGS}
.PHONY: generate

build:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -a .
.PHONY: build

check:
	go vet ${PKGS}
.PHONY: check

test:
	go test -v ${PKGS} -cover -race -p=1
.PHONY: test

image: build
	docker build -t ${PREFIX}/kubelet-vault-registrar:${TAG} .
.PHONY: image

push: image
	docker push ${PREFIX}/kubelet-vault-registrar:${TAG}
.PHONY: push

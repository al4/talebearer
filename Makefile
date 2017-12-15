## Makefile

.DEFAULT_GOAL := build
BUILD_NUMBER ?= SNAPSHOT-$(shell git rev-parse --abbrev-ref HEAD)

GOOS ?= $(uname -s)
GOARCH ?= amd64
export GOOS
export GOARCH

build: docker

clean:
	go clean

install: clean
	go install .

test:
	docker build --target=builder .

lint:
	gometalinter --deadline=240s --enable-gc --tests --aggregate --disable=gotype --sort=path -e '^\.\./\.\.' ./...

docker:
	docker build -t talebearer:$(BUILD_NUMBER) .
	docker build -t talebearer:latest .


.PHONY: install, build, docker, test
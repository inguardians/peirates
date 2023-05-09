PACKAGES:=$(shell go list ./... | grep -v /vendor/)

default: lint

gofmt:
	go fmt ./...

lint: gofmt
	$(GOPATH)/bin/golint $(PACKAGES)
	$(GOPATH)/bin/golangci-lint run
	$(GOPATH)/bin/gosec -quiet -no-fail ./...

update-deps:
	go get -u ./...
	go mod tidy
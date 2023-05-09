PACKAGES:=$(shell go list ./... | grep -v /vendor/)

default: lint

gofmt:
	go fmt ./...

lint: gofmt
	$(GOPATH)/bin/golint $(PACKAGES)
	$(GOPATH)/bin/gosec -quiet -no-fail ./...
	$(GOPATH)/bin/golangci-lint run
	
update-deps:
	go get -u ./...
	go mod tidy
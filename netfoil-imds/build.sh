#!/bin/bash

set -e

GOOS=linux GOARCH=amd64 GO111MODULE=on CGO_ENABLED=0 go build -trimpath -o netfoil-imds -buildmode=pie ../cmd/netfoil-imds/main.go

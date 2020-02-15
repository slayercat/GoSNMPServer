#!/bin/sh

go test -v ./...  -coverpkg ./... -coverprofile=coverage.txt -covermode=atomic
go tool cover -html=coverage.txt  -o tCoverage.html

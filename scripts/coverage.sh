#!/bin/bash

go get github.com/go-playground/overalls && go get github.com/mattn/goveralls

overalls -project=github.com/openconfig/lsdbparse -covermode=count -ignore=".git,pkg"
goveralls -coverprofile=overalls.coverprofile -service travis-ci



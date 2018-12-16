#!/bin/bash -eu
#
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#!/bin/bash

# Hack to ensure that if we are running on OS X with a homebrew installed
# GNU sed then we can still run sed.
runsed() {
  if hash gsed 2>/dev/null; then
    gsed "$@"
  else
    sed "$@"
  fi
}

git clone https://github.com/openconfig/public.git
git clone https://github.com/mbrukman/autogen.git
mkdir deps && cp ../../third_party/*.yang deps
go run $GOPATH/src/github.com/openconfig/ygot/generator/generator.go -path=public,deps -output_file=oc.go \
  -package_name=oc -generate_fakeroot -fakeroot_name=device -compress_paths=true \
  -exclude_modules=ietf-interfaces,openconfig-acl,openconfig-bgp,openconfig-interfaces,openconfig-local-routing \
  -generate_getters \
  -generate_append \
  yang/parse-isis-deviations.yang \
  public/release/models/network-instance/openconfig-network-instance.yang
gofmt -w -s oc.go
autogen/autogen --no-code --no-tlc -c "Google LLC" -l apache -i oc.go
rm -rf public autogen deps

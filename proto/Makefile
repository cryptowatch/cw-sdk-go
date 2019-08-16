SHELL := /bin/bash

CW_BUILD_VERSION_TAG := $(shell cat $(CW_REPO_ROOT)/tools/dev/docker-images/cw-build/version_tag)

ifndef CW_BUILD_IMAGE_VERSION
  # We're outside of the cw-build docker container, so go through docker run.
  CW_BUILD_VERSION_TAG := $(shell cat $(CW_REPO_ROOT)/tools/dev/docker-images/cw-build/version_tag)
  PROTOC_IMG=gitlab-omgwehaveit.cwix.org:5005/cryptowatch/dev/cw-build:$(CW_BUILD_VERSION_TAG)
  DOCKER_CW_REPO_ROOT=/root/cryptowatch
  DOCKER_CW_REPO_ROOT_IDIOMATIC=/root/code.cryptowat.ch

  DOCKER_CMD=docker run --rm -v $(CW_REPO_ROOT):$(DOCKER_CW_REPO_ROOT) \
    -w $(DOCKER_CW_REPO_ROOT)/proto -e CW_REPO_ROOT=$(DOCKER_CW_REPO_ROOT)

  PROTOC=$(DOCKER_CMD) --entrypoint protoc $(PROTOC_IMG)
  PROTOLOCK=$(DOCKER_CMD) --entrypoint protolock $(PROTOC_IMG)

else
  # We're already inside of the cw-build docker container,
  # so use protoc and protolock directly.

  PROTOC=protoc
  PROTOLOCK=protolock
endif


.PHONY: proto
proto: proto.status proto.gen.unversioned proto.gen.versioned proto.lock

.PHONY: proto.status
proto.status:
	$(PROTOLOCK) status

.PHONY: proto.lock
proto.lock:
	$(PROTOLOCK) commit

.PHONY: proto.gen.unversioned
proto.gen.unversioned:
	$(PROTOC) --gofast_out=. -I. markets/*.proto
	$(PROTOC) --gofast_out=. -I. client/*.proto
	$(PROTOC) --gofast_out=Mmarkets/market.proto=code.cryptowat.ch/proto/markets,Mmarkets/pair.proto=code.cryptowat.ch/proto/markets,Mmarkets/asset.proto=code.cryptowat.ch/proto/markets,Mmarkets/index.proto=code.cryptowat.ch/proto/markets,Mclient/client.proto=code.cryptowat.ch/proto/client:. -I. stream/*.proto
	$(PROTOC) --gofast_out=Mstream/stream.proto=code.cryptowat.ch/proto/stream,Mclient/client.proto=code.cryptowat.ch/proto/client:. -I. broker/*.proto
	$(PROTOC) --gofast_out=Mclient/client.proto=code.cryptowat.ch/proto/client:. -I. trigger/*.proto
	$(PROTOC) --gofast_out=Mgoogle/protobuf/duration.proto=github.com/gogo/protobuf/types,plugins=grpc:. -I. observer/*.proto

# -------------------------
# Versioned protobuf files.
# -------------------------

# Logic bellow is responsible for collecting directories within proto/cryptowatch where *.proto files are located.
# Thanks to this, after adding a new .proto file, no additional changes are required,
# necessary targets will be "generated" automatically.
rwildcard=$(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2) $(filter $(subst *,%,$2),$d))
files:=$(call rwildcard, cryptowatch/, *.proto)
directories:=$(sort $(dir $(files)))
targets = $(addprefix proto.gen.versioned.direct/, $(directories))
proto_root = $(shell cd ../../ && pwd)

.PHONY: proto.gen.versioned
proto.gen.versioned:
	docker run --rm \
		-w $(DOCKER_CW_REPO_ROOT_IDIOMATIC)/proto \
		-e CW_REPO_ROOT=$(DOCKER_CW_REPO_ROOT_IDIOMATIC) \
		-v $(CW_REPO_ROOT):$(DOCKER_CW_REPO_ROOT_IDIOMATIC) \
		--entrypoint make $(PROTOC_IMG) \
		-- proto.gen.versioned.direct

.PHONY: proto.gen.versioned.direct
proto.gen.versioned.direct: $(targets)

$(targets): proto.gen.versioned.direct/%: %
	protoc -I=. -I=${proto_root} --go_out=plugins=grpc:${proto_root} ${proto_root}/code.cryptowat.ch/proto/$(patsubst %/,%,$(<))/*.proto
	mockery -case=underscore \
		-all \
		-outpkg=$(shell basename $(shell cd ${proto_root}/code.cryptowat.ch/proto/$(<)/../ && pwd))mock \
		-dir=./$(<) \
		-output="./$(patsubst %/,%,$(<))mock"
	echo "LOL: ${<}"
	cd ../ && $(MAKE) go-format/proto/$(<)

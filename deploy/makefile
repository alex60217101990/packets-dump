include make-helpers/makefile
PROJECTNAME=$(shell basename "$(PWD)")
# golang block
GOCMD := go
GOBUILD := CGO_ENABLED=0 GOOS=linux $(GOCMD) build
# CGO_ENABLED=0
GOCLEAN := $(GOCMD) clean
GOGET := $(GOCMD) get
CLANG := clang
CLANG_INCLUDE := -I$(shell find .. -name \elf-files -type d)

GO_SOURCE := $(shell find .. -name \dump.go -type f)
GO_BINARY := dump

EBPF_SOURCE := $(shell find .. -name \dump.c -type f)
EBPF_SOURCE_FW := $(shell find .. -name \kern.c -type f)
EBPF_SOURCE_DROP := $(shell find .. -name \fw_1.c -type f)
EBPF_BINARY := ../tmp/dump.elf
EBPF_BINARY_FW := ../tmp/fw.elf
EBPF_BINARY_DROP := ../tmp/fw_1.elf

# all: build_bpf build_go

# build_bpf: $(EBPF_BINARY)

# build_go: $(GO_BINARY)

# clean:
# 	$(GOCLEAN)
# 	rm -f $(GO_BINARY)
# 	rm -f $(EBPF_BINARY)

# $(EBPF_BINARY): $(EBPF_SOURCE)
# 	$(CLANG) $(CLANG_INCLUDE) -O2 -target bpf -c $^  -o $@

# $(GO_BINARY): $(GO_SOURCE)
# 	$(GOBUILD) -v -o $@

compile: 
	@printf "${COLOR_LIGHT_CYAN}Compile service...${COLOR_NC}\n"


clean:
	@printf "${COLOR_YELLOW}Clear all...${COLOR_NC}\n"
	$(GOCLEAN)
	rm -f ../tmp/$(GO_BINARY)
	rm -f $(EBPF_BINARY)

ebpf-elf-build: $(EBPF_SOURCE)
	@printf "${COLOR_LIGHT_PURPLE}Building .elf binary...${COLOR_NC}\n"
	$(CLANG) $(CLANG_INCLUDE) -O2 -target bpf -c $^  -o $(EBPF_BINARY)
	$(CLANG) $(CLANG_INCLUDE) -O2 -target bpf -c $(EBPF_SOURCE_FW)  -o $(EBPF_BINARY_FW)
	$(CLANG) $(CLANG_INCLUDE) -O2 -target bpf -c $(EBPF_SOURCE_DROP)  -o $(EBPF_BINARY_DROP)

go-build:
	$(GOCMD) clean -modcache
	@printf "$(COLOR_LIGHT_GREEN)Building binary... $(GO_BINARY)$(bin_name)$(COLOR_NC)\n"
	# $(GOCMD) mod download
ifdef bin_name
	$(GOBUILD) -v -x -i -a -installsuffix cgo -pkgdir ../tmp/pkgs -o ../tmp/$(bin_name) $(GO_SOURCE)
else
	$(GOBUILD) -v -x -i -a -installsuffix cgo -pkgdir ../tmp/pkgs -o ../tmp/$(GO_BINARY) $(GO_SOURCE)
endif

my_test:
ifdef toto
	@echo 'toto is defined $(toto)'
else
	@echo 'no toto around'
endif

## go-get: Install .mod file dependency.
go-get:
	@printf "${COLOR_LIGHT_GREEN}Install dependencies...${COLOR_NC}\n"
	$(GOGET) -d ../...

.PHONY: help
all: help
help: Makefile
	@echo
	@echo " Choose a command run in "$(PROJECTNAME)":"
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@echo


# make bin_name=333 go-build OR make go-build


# docker run --security-opt no-new-privileges --cap-add=SYS_ADMIN -it xdp_dump /bin/bash
# sudo ./xdp_sample_pkts_user -d veth-basic02 -F


# gcc -Wall -Wextra -o example -I../internal/ ../internal/elf-files/uuid4.c ../internal/elf-files/test.c

# sudo docker build --build-arg MOD_FILE="$(cat ./go.mod)" --build-arg SUM_FILE="$(cat ./go.sum)" -f ./deploy/Dockerfile -t dump .

# curl -s localhost:80 >/dev/null && echo Success. || echo Fail.

# docker inspect 115c71d8e865 --format='{{.Id}}'
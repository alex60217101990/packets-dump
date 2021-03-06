# # Dockerfile References: https://docs.docker.com/engine/reference/builder/
# # Start from the latest golang base image
# FROM golang:latest as builder
# # Add Maintainer Info
# LABEL maintainer="alex6021710@gmail.com"

# ENV CGO_ENABLED 0
# # ENV GO111MODULE on
# ENV GOPROXY direct
# ENV GOSUMDB off
# ENV GOOS linux

# # Set the Current Working Directory inside the container
# WORKDIR /app

# # Copy go mod and sum files
# ARG MOD_FILE
# RUN echo "$MOD_FILE" > ./go.mod
# ARG SUM_FILE
# RUN echo "$SUM_FILE" > ./go.sum

# # Copy the source from the current directory to the Working Directory inside the container
# COPY ./ ./

# # Download all dependancies. Dependencies will be cached if the go.mod and go.sum files are tracing changed
# RUN go mod download

# RUN mkdir -p /tmp/pkgs && chmod 777 /tmp/pkgs

# # Build the Go app
# # RUN CGO_ENABLED=0 GOOS=linux go build -v -a -installsuffix cgo \
# #     -o dump ./cmd/dump.go

# RUN go build -v -x -i \
#     -a -installsuffix cgo -pkgdir /tmp/pkgs \
#     -o dump ./cmd/dump.go

######### Start a new stage from scratch #######
# FROM alpine:latest 

# LABEL maintainer="alex6021710@gmail.com"

# RUN apk add --no-cache --upgrade bash
# RUN apk --no-cache add ca-certificates

# RUN apk add --update \
#   clang \
#   llvm \
#   gcc \
#   apk-tools \
#   linux-headers

# WORKDIR /root/

# COPY ./dump .
# COPY ./dump.elf .

# RUN chmod +x ./dump

# CMD ["./dump", "-iface", "eth0"]





FROM ubuntu:18.04 

LABEL maintainer="alex6021710@gmail.com"

RUN apt-get update && apt-get install -y locales sudo && rm -rf /var/lib/apt/lists/* \
    && localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
ENV LANG en_US.utf8

WORKDIR /root/

COPY ./dump .
COPY ./dump.elf .

RUN chmod +x ./dump

CMD ["sudo", "./dump", "-iface", "eth0"]
# Linux regression and packet-analysis tools. Browser binaries are supplied
# separately when reproducing a reference version; see README.md.
FROM golang:1.27.4-bookworm AS go
FROM node:26.13.1-bookworm-slim AS node
FROM ubuntu:26.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential ca-certificates curl git python3 \
    iproute2 ethtool tcpdump tshark openssl libnss3-tools xvfb \
    && rm -rf /var/lib/apt/lists/*

COPY --from=go /usr/local/go /usr/local/go
COPY --from=node /usr/local/bin/node /usr/local/bin/node
ENV PATH="/usr/local/go/bin:${PATH}" GOPATH=/go
WORKDIR /work/surf

CMD ["bash"]

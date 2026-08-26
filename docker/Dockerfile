FROM ubuntu:24.04

ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        sudo \
        git \
        curl \
        bash \
    && rm -rf /var/lib/apt/lists/*

# Prebuilt binary from the compile job. Do not RUN go build here.
# Context must contain agentguard-amd64 and/or agentguard-arm64 (TARGETARCH).
COPY agentguard-${TARGETARCH} /usr/local/bin/agentguard
RUN chmod 0755 /usr/local/bin/agentguard

# ubuntu:24.04 already has user ubuntu (uid 1000). Do not useradd -u 1000.
RUN echo 'ubuntu ALL=(ALL) NOPASSWD: /usr/local/bin/agentguard' > /etc/sudoers.d/ubuntu \
    && chmod 0440 /etc/sudoers.d/ubuntu

WORKDIR /workspace
USER ubuntu

# Copyright 2026-Present Datadog, Inc. https://www.datadoghq.com/
# SPDX-License-Identifier: Apache-2.0
#
# CI image for the publish stage (Ubuntu 24.04 LTS).
# Built multi-arch (linux/amd64 + linux/arm64) by docker_build_job.
#
# Bakes in: build toolchain, Rust, cargo-nextest, AWS CLI v2, and jq so that
# publish and any pre-publish scripting work out of the box without downloading
# tools at runtime.

ARG BASE_IMAGE="registry.ddbuild.io/images/mirror/ubuntu:24.04"
FROM ${BASE_IMAGE} AS base

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq \
  && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
    jq \
    unzip \
  && rm -rf /var/lib/apt/lists/*

# AWS CLI v2 — installed from the official Amazon bundle so the version is
# pinned and reproducible across architectures.
RUN ARCH=$(uname -m) \
  && curl -sSL "https://awscli.amazonaws.com/awscli-exe-linux-${ARCH}.zip" -o /tmp/awscliv2.zip \
  && unzip -q /tmp/awscliv2.zip -d /tmp/awscli \
  && /tmp/awscli/aws/install \
  && rm -rf /tmp/awscliv2.zip /tmp/awscli \
  && aws --version

FROM base AS rust

ARG RUST_VERSION="1.84.1"

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y \
        --default-toolchain "${RUST_VERSION}" \
        --no-modify-path \
        --profile minimal \
  && chmod -R a+w "$RUSTUP_HOME" "$CARGO_HOME"

RUN rustc --version && cargo --version

RUN cargo install --locked 'cargo-nextest@0.9.96'

FROM rust AS final

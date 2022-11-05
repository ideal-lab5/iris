FROM phusion/baseimage:0.11 as builder
LABEL maintainer="driemworks@idealabs.network"
LABEL description="This is the build stage for Iris. Here we create the binary."

ENV DEBIAN_FRONTEND=noninteractive

ARG PROFILE=release
WORKDIR /iris

COPY . /iris

RUN apt-get update && \
	apt-get dist-upgrade -y -o Dpkg::Options::="--force-confold" && \
	apt-get install -y cmake pkg-config libssl-dev git clang && \
	apt-get install -y wget

# build iris
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y && \
	export PATH="$PATH:$HOME/.cargo/bin" && \
	rustup toolchain install nightly && \
	rustup target add wasm32-unknown-unknown --toolchain nightly && \
	rustup default stable && \
	cargo build "--$PROFILE"

# ===== SECOND STAGE ======

FROM phusion/baseimage:0.11
LABEL maintainer="driemworks@idealabs.network"
LABEL description="This is the 2nd stage: a very small image where we copy the Iris binary."
ARG PROFILE=release

# add user
RUN useradd -m -u 1000 -U -s /bin/sh -d /iris iris
COPY --from=builder /iris/target/$PROFILE/iris-node /usr/local/bin

# checks
RUN ldd /usr/local/bin/iris-node && \
	/usr/local/bin/iris-node --version

# Shrinking
RUN rm -rf /usr/lib/python* && \
	rm -rf /usr/bin /usr/sbin /usr/share/man

USER iris
# expose node endpoints
EXPOSE 30333 9933 9944 9615
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/iris-node"]
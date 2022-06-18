# Iris Node

The official Iris implementation.

![sponsored by web3 foundation](./docs/web3%20foundation%20grants_black.jpg)


## Getting Started

Follow the steps below to get started with the Iris node.

## Installation

There are three ways to install iris, either building the source code, building a docker image, or simply installing from docker.

### Build from Sources

``` bash
git clone https://github.com/ideal-lab5/iris.git
cd iris
cargo +nightly build --release
```

### Docker

Install from the docker hub
`docker pull ideallabs/iris`

**OR**

From the latest sources, build the docker image:
`docker build -t ideallabs/iris -f /Dockerfile .`

## Running

### From Sources

``` bash
# purge the local chain data
./target/release/node-template purge-chain --base-path /tmp/alice --dev -y
# run the build
./target/release/iris-node \
  --base-path /tmp/alice \
  --dev \
  --alice \
  --port 30333 \
  --ws-port 9944 \
  --rpc-port 9933 \
  --rpc-cors all \
  --ws-external \
  --rpc-external \
  --rpc-methods=unsafe
```

Note: to specify a bootnode, use the bootnodes parameter. ex: `--bootnodes /ip4/127.0.0.1/tcp/30333/p2p/12D3KooWEdUQFXhAF4fu9hqRTWqsigioyjatRKRZ7mwyQCBoWyK3`

### From Docker

``` bash
docker run -p 9944:9944 \
  -p 9933:9933 \
  -p 30333:30333 \
  -p 9615:9615 \
  -it \
  --rm \
  --name iris-alice \
  ideallabs/iris \
  --dev --ws-external --rpc-external \
  --node-key 0000000000000000000000000000000000000000000000000000000000000001
```

## Interacting with your node

*See the [tech overview](../src/chapter_3.md) for information on extrinsics, rpc, etc.*

### PolkadotJs

As the UI undergoes development, the most *stable* way to interact with your node is to use the default [polkadotjs ui](https://polkadot.js.org/).

### The Iris UI

The Iris UI provides a mechanism to add and retrieve data from Iris, to create an asset class, mint assets, privision data access, and manage both asset classes and assets.

If you intend to add data to Iris, you must also run an IPFS node locally. This holds for running from sources as well as the docker image. Run IPFS with `ipfs daemon`.

### Running from Sources

``` bash
git clone https://github.com/ideal-lab5/ui.git
cd ui
npm i
REACT_APP_IPV4=<your ipv4> npm start
```

### Running from Docker

``` bash
docker pull ideallabs/iris-ui
# replace w.x.y.z with your ip
docker run -it --rm -p 3000:3000 -e "REACT_APP_IPV4=w.x.y.z" ideallabs/iris-ui
```

## Testing

Run the unit tests with `cargo +nightly test iris`.

### Coverage

We aim for a minimum of 80% coverage on new code.

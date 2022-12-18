<p align="center">
  <img width="600" height="600" src="./docs/iris_logo_0.png">
</p>

# The official Iris node implementation

Iris is a decentralized network built with [Substrate](https://substrate.dev/) and [IPFS](https://ipfs.io) for creating, owning, and sharing secret data. 

* :point_right: Learn more about the project and team at https://idealabs.network

* :blue_book: Read our [technical docs](https://ideal-lab5.github.io/introduction.html) to learn about the inner working of Iris

<p align="left">
  <img width="500" height="250" src="./docs/web3%20foundation%20grants_black.jpg">
</p>


## Getting Started

Follow the steps below to get started with the Iris node or take a look at our [technical docs](https://ideal-lab5.github.io/introduction.html) for more in depth guides.

## Building

### Prerequisites

- [Install Rust](https://www.rust-lang.org/tools/install) and dependencies

``` bash
curl https://sh.rustup.rs -sSf | sh
rustup update
sudo apt install build-essential git clang libclang-dev pkg-config libssl-dev
```

- [Install and Configure IPFS](#ipfs-installation-and-configuration)

### Build

Clone the main repo and build the node. This can take up to 10 minutes.

``` bash
git clone https://github.com/ideal-lab5/iris.git
cd iris
cargo +nightly build --release
```

#### Run

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
  --rpc-methods=unsafe \
  --validator \
  --node-key 0000000000000000000000000000000000000000000000000000000000000001
```

Note: to specify a bootnode, use the bootnodes parameter. ex: `--bootnodes /ip4/127.0.0.1/tcp/30333/p2p/12D3KooWEdUQFXhAF4fu9hqRTWqsigioyjatRKRZ7mwyQCBoWyK3`

### Run from Docker

#### Prerequisites

- [install Docker](https://docs.docker.com/getdocker/)

Install from the docker hub
`docker pull ideallabs/iris`

**OR**

From the latest sources, build the docker image:
`docker build -t ideallabs/iris -f /Dockerfile .`

#### Run

``` bash
# run as validator node (e.g. first node)
docker run -p 9944:9944 \
  -p 9933:9933 \
  -p 30333:30333 \
  -p 9615:9615 \
  -it \
  --rm \
  --name iris-alice \
  ideallabs/iris \
  --dev --ws-external --rpc-external --validator --alice \
  --node-key 0000000000000000000000000000000000000000000000000000000000000001
```

## Interacting with your node

See [here](../developers/data_ingestion/md) for a more in depth treatment of 

### IPFS Installation and Configuration

- [install IPFS](https://docs.ipfs.tech/install/) and configure

``` bash
wget https://dist.ipfs.io/kubo/v0.14.0/kubo_v0.14.0_linux-amd64.tar.gz
tar -xvzf kubo_v0.14.0_linux-amd64.tar.gz
cd kubo
sudo bash install.sh
ipfs --version
```

Update your ipfs configuration to specify the IPFS bootstrap nodes exposed by the testnet. This step will allow Iris gateway nodes to find your data.

First, ensure that your ipfs node is reachable 

``` bash
ipfs config Addresses.API "/ip4/0.0.0.0/tcp/5001"
ipfs config Addresses.Gateway "/ip4/0.0.0.0/tcp/8080"
ipfs config --json API.HTTPHeaders.Access-Control-Allow-Origin "[\"*\"]"
ipfs config --json API.HTTPHeaders.Access-Control-Allow-Credentials "[\"true\"]"
```

This step is optional. Generally, finding peers in the IPFS DHT is rather slow. Due to this, using a public IPFS network can mean that the calls to find data take a very long time, which causes validator nodes to be  removed from the validator set. Due to this, it is recommended that you either use the [swarm.key](https://raw.githubusercontent.com/ideal-lab5/iris/main/swarm.key) in use by Iris or generate your own.

Generate a swarm key:

``` bash
echo -e "/key/swarm/psk/1.0.0/\n/base16/\n`tr -dc 'a-f0-9' < /dev/urandom | head -c64`" > ~/.ipfs/swarm.key
```

and share the generated file with each validator in your testnet.

Now, configure Available bootstrap nodes are available in the 'bootstrap nodes' runtime storage map in the ipfs pallet.

``` bash
# fetch the swarm.key and copy it to your .ipfs folder
wget https://raw.githubusercontent.com/driemworks/iris/main/swarm.key
# reconfigure bootstrap nodes
ipfs bootstrap rm --all
# replace the 
ipfs bootstrap add /ip4/<ip address>/tcp/4001/p2p/<peerID>
```

## Generating a custom chain spec

``` bash
cargo +nightly build --release
./target/release/iris-node build-spec --chain=dev --raw --disable-default-bootnode > iris.json
```

## Testing

Run the unit tests with `cargo +nightly test iris`.

## Guidelines

We aim for a minimum of 80% coverage on new code.

#!/usr/bin/env bash
# This script is meant to be run on Unix/Linux based systems
# The goal of this script is to initialize Iris along with all requried dependencies

# set -e

# echo "*** Initializing WASM build environment"

# if [ -z $CI_PROJECT_NAME ] ; then
#    rustup update nightly
#    rustup update stable
# fi

# rustup target add wasm32-unknown-unknown --toolchain nightly

# verify local ipfs installation
# cd ~
# echo "Verifying IPFS installation"

# if ! command -v <the_command> &> /dev/null
# then
#     read -p "IPFS is not detected. Press any key to continue (to install IPFS), or ctrl+C to quit."
#     echo "Installing IPFS"
#    # install IPFS (kubo)
#    wget https://dist.ipfs.io/kubo/v0.16.0/kubo_v0.16.0_linux-amd64.tar.gz
#    tar -xvzf kubo_v0.16.0_linux-amd64.tar.gz
#    cd kubo
#    sudo ./install.sh
#    ipfs --version

#    # Cleanup
#    cd ~
#    rm kubo_v0.16.0_linux-amd64.tar.gz
# fi

# # configure IPFS: This assumes you have installed .ipfs in your root dir
# echo "Configuring IPFS"
# ipfs init
# ipfs config Addresses.API "/ip4/0.0.0.0/tcp/5001"
# ipfs config Addresses.Gateway "/ip4/0.0.0.0/tcp/8080"
# ipfs config --json API.HTTPHeaders.Access-Control-Allow-Origin "[\"*\"]"
# ipfs config --json API.HTTPHeaders.Access-Control-Allow-Credentials "[\"true\"]"
# ipfs bootstrap rm --all
# ipfs bootstrap add /ip4/18.118.65.202/tcp/4001/p2p/12D3KooWJ5wuqGnr6u8XV6FeBbP1MBBamUpavwfotRag2JnTrF9p

# cd .ipfs
# wget https://raw.githubusercontent.com/ideal-lab5/iris/main/swarm.key
# cd ~

# start the daemon
# ipfs daemon 

# pull the latest iris docker image
docker pull ideallabs/iris
# pull the latest chain spec
wget https://raw.githubusercontent.com/ideal-lab5/iris/main/iris.json
# run an iris node
docker run --add-host host.docker.internal:host-gateway -p 9944:9944 -p 9933:9933 -p 30333:30333 -p 9615:9615 -v ~/iris.json:/mnt/iris.json -it --rm --name iris-node ideallabs/iris --chain=/mnt/iris.json --rpc-cors all --unsafe-ws-external --rpc-external --rpc-methods=unsafe

# pull the latest ui image
docker pull ideallabs/iris-ui
# run the image on port 3000
docker run --rm -p 3000:3000 ideallabs/iris-ui
#!/usr/bin/env bash
wget https://dist.ipfs.io/kubo/v0.14.0/kubo_v0.14.0_linux-amd64.tar.gz
tar -xvzf kubo_v0.14.0_linux-amd64.tar.gz
cd kubo
sudo bash install.sh
ipfs --version
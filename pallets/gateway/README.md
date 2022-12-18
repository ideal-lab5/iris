# Gateway Pallet

The gateway pallet enables nodes to stake tokens to act as IPFS gateways for the network.

## Overview

### Terminology

* `gateway`: In the context of IPFS, a gateway acts as a point of ingress and egress to the IPFS network.

### Goals

The goal of this pallet:
* allow validators to stake tokens to become a gateway
* specify preferences as a gateway (e.g. max storage capacity)

## Interface

### Dispatachable Functions

* `bond`: Bond a minimum number of tokens to be staked
* `bond_extra`: Bond tokens on top of what has already been bonded
* `unbond`: Unbond tokens
* `declare_gateway`: Declare your gateway preferences after bonding the minimum number of required tokens.

### Public Functions

## Usage

### Prerequisites

### Simple Code Snippet

## Assumptions
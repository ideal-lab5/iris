# Authorities Pallet
This pallet allows for a dynamic set of authorities within the proof of authority network.

## Overview 

The authorities pallet provides functionality to manage the validator set, to provide integration with the Session pallet, to configure the genesis state of validators and proxies, and to generate new keys for proxies. It also integrates with the im-online pallet to automatically remove offline storage providers. The pallet uses the Session pallet and implements related traits for session management. Currently it uses periodic session rotation provided by the session pallet to automatically rotate sessions. For this reason, the validator addition and removal becomes effective only after 2 sessions (queuing + applying).

### Terminology

* authority: An authority is a validator node, or potentially any node with elevated privileges
* proxy: A proxy node is a node who has an x25519 keypair and is responsible for reencryption.
* x25519: Refers to [the key exchange on curve 25519](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/x25519/).

### Goals

The goal of this module is to enable a dynamic and controllable set of validator nodes in a proof of authority network. Further, it ensures that all validators can act in the capacity of a proxy node. It makes the following possible:

* set authority genesis state
* set proxy node genesis state
* generate new x25519 keys for authorities
* validator management
  * remove offline
  * allow root to add/remove/modify validator set as desired (in PoA network) 

## Interface

### Dispatachable Functions

* `add_validator`: Add a non-validator node as a valdiator. Origin must be root.
* `remove_validator`: Remove a validator node as a valdiator. Origin must be root.
* `add_validator_again` Add a validator back to the active set if it has gone offline.
* `insert_key`: Insert a new x25519 public key into runtime storage. This should only be called by OCWs.

### Public Functions

* `validators`: Get the set of active validators
* `x25519_public_key`: Get a validator's x25519 pubkey (if it exists)

## Usage

In the snippet below, we show how you would:

* get the active validator set
* get the current era index

### Prerequisites

Import the Authorities module and types and derive your runtime's configuration traits from the Authories module trait.

### Simple Code Snippet

TODO

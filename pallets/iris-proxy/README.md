# IrisProxy Pallet

The IrisProxy pallet enables the threshold proxy reencryption system in use by Iris.

## Goals

The goal of this module is to provide the mechanisms for encryption, reencryption, reencapsulation, and decryption of data. 

## Overview 



### Terminology

* `data_owner`: A data owner is any node who owns an on-chain data asset class
* `data_consumer`: A data consumer is any node has gained authorization to decrypt the data
* `delegator`: A delegator is any node who delegates decryption rights to another node. Usually this will take the form of a rule executor smart contract.
* `delegatee`: A delegatee is any node who has had decryption rights delegated to it. In general, we can use this synonymously with 'authorized data consumer'.
* `proxy`: A proxy node is a validator node who has been selected to reencrypt some data

### Goals

This module enables:

* data encryption via RPC
* data decryption via RPC
* reencryption of encrypted data by proxy nodes
* reencapsulation of key fragments by validator nodes

## Interface

### RPC

The RPC endpoints whose logic exists in this pallet facilitate encryption of data and decryption of data through the TPRE system. These two endpoints are the pentultimate ingress and egress points for plaintext in the Iris blockchain.

#### Encrypt

The `iris_encrypt` RPC allows a potential data owner to encrypt data and stage encryption artifacts into runtime storage, and ciphertext is returned from the endpoint.

#### Decrypt

The `iris_decrypt` RPC allows an authorized data consumer to decrypt some ciphertext for which they've received reencryption keys.

### Dispatachable Functions

### Public Functions

## Usage

### Prerequisites

### Simple Code Snippet

## Assumptions
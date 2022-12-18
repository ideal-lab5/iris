# IPFS pallet

This pallet is the core integration with an external IPFS instance. It contains both configuration and implementation.

### Terminology

* `IPFS`: The Interplanetary File System

## Goal

The goal of this pallet is to build a bridge between Iris identities and IPFS identities. This module provides functionality to:

* communicate with an external IPFS instance
* configure an IPFS instance based on preferences specified in the Gateway pallet
* The main OCW loop exists in this pallet. This loop:
  * ensures proxies have valid x25519 pubkeys 
  * build bridge between Iris and IPFS
  * process items in the ingestion queue
  * process reencryption requests
  * process reencapsulation requests

### Dispatachable Functions

### Public Functions

## Usage

### Prerequisites

### Simple Code Snippet

## Assumptions
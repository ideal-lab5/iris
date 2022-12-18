# Data Assets
This pallet contains functions that allow users to create and manage asset classes and derived assets which are associated with some data that exists in an offchain storage system.

## Overview

The functionality provided by this pallet is specifically oriented towards 'data owners'.

### Terminology

* `data_owner`: The owner of some data
* `asset_id`: An asset id is an unsigned 32 bit integer that unqiue identifies an on-chain data asset class

### Goals

The goals of this module are:

* create requests for gateways to ingest data
* track data asset class metadata (e.g. CID of ciphertext)

## Interface

### Dispatachable Functions

* `create_request`: Submit an on-chain request to a gateway to ingest data

### Public Functions

### Traits

#### ResultsHandlers

* `create_asset_class`: Create a new asset class

#### MetadataProvider

* `get`: Fetch the metadata associated with an asset id

## Usage

### Prerequisites

### Simple Code Snippet

## Assumptions
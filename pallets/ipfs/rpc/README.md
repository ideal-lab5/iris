# Data Ingestion/Ejection RPC

RPC interface to handle data ejection and ingestion via proxy nodes

## Goal

## Authorization

The RPC endpoints described below act essentially as permissioned communication with the underlying ipfs node. That is, they provide an authorization layer between a node and a ipfs, which is handled by the proxy nodes.

## Data Ingestion

TODO

## Data Ejection

## Developers

### Guide to updating rpc endpoints

Update required lines in:

- rpc/lib.rs
- rpc/runtime-api/lib.rs
- runtime/lib.rs
- module/lib.rs
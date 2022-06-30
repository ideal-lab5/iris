# Proxy Pallet

The proxy pallet is used to manage funds staked by proxy nodes.

While Iris remains a proof of authority network and has not yet implemented a threshold encrypted system, we stipulate that only authorities have the right to become proxies.

The design of this pallet is inspired by a proof of stake system which may be used by validators of a network, however, there are many differences between the way validators would operate and how proxies operate.

## Goals

The goal of this module is to manage the funds staked by nodes that are providing proxy services to the network. A proxy node reads from two distinct queues which are populated with commands initiated by data owners and data consumers.

The `IngestionQueue` contains commands initiated by data owners to ingest data into the underlying IPFS network and to create a new asset class on their behalf.

The `EjectionQueue` contains commands initiated  by data consumers to eject data from the underlying IPFS network when authorized consumers make such a request. The proxy is not responsible for authorizing the consumer, only for verifying the authorization.

## Staking

* staking: An authority must stake an additional 50 (TBD) IRIS in order to be eligible to proxy requests.
* unstaking: A proxy can reduce or reclaim its stake at any point in time, as long as there are no commands which it is currently responsible to execute.
* chilling: A proxy node can choose to 'chill' at any time, wherein its stake is still maintained but it will not be elected to proxy requests.
* freezing: Any proxy node whose stake has been reduced below the threshold or who has been offline for greater than 1000 (TBD) sessions is frozen. In order to reclaim its stake, the node must first reactivate itself by going online.

## Rewards

Proxy nodes are rewarded based on the requests from the `IngestionQueue` and the `EjectionQueue` that they proxy. Unlike a staking mechanism for validator nodes, rhe tokens that proxy nodes recieve as a reward originate from the account who added the command to either queue initially.

### Reward for exeucting write commands

In this scenario, a proxy node is responsible

### Rewards for executing read commands

## Slashing

We use a slashing mechanism to discourage poor behavior. Further, this mechanism punishes nodes who do not properly proxy requests to the underlying ipfs node. To be explicity, we slash funds based on:

* time to process requests: if a live proxy doesn't respond from a request to execute an ipfs function, we slash based on the amount of time that they have exceeded. If they never respond but remain online, we continue slashing until their staked amount falls under the minimum stake amount, after which they are marked ineligible.

## Election Algorithm

The election algorithm is used to determine which proxy nodes are responsible for proxying specific requests in any individual data queue. The currently used algorithm is a modification of phragmen, taking into account total storage capacity of a proxy node's underlying ipfs node.

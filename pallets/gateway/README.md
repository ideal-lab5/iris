# Proxy Pallet

The proxy pallet is used to manage funds staked by proxy nodes.

While Iris remains a proof of authority network and has not yet implemented a threshold encrypted system, we stipulate that only authorities have the right to become proxies.

The design of this pallet is inspired by a proof of stake system which may be used by validators of a network, however, there are many differences between the way validators would operate and how proxies operate.

## Goals

The goal of this module is to manage the funds staked by nodes that are providing proxy services to the network. A proxy node reads from two distinct queues which are populated with commands initiated by data owners and data consumers.

The `IngestionQueue` contains commands initiated by data owners to ingest data into the underlying IPFS network and to create a new asset class on their behalf.

The `EjectionQueue` contains commands initiated  by data consumers to eject data from the underlying IPFS network when authorized consumers make such a request. The proxy is not responsible for authorizing the consumer, only for verifying the authorization.

## Configuration

* min_proxy_bond: The minimum amount of tokens that a proxy must bond
* max_proxy_count: The maximum number of proxies before we block new proxies from joining

## Staking

* staking: An authority must stake an additional 50 (TBD) IRIS in order to be eligible to proxy requests.
* unstaking: A proxy can reduce or reclaim its stake at any point in time, as long as there are no commands which it is currently responsible to execute.
* chilling: A proxy node can choose to 'chill' at any time, wherein its stake is still maintained but it will not be elected to proxy requests.
* freezing: Any proxy node whose stake has been reduced below the threshold or who has been offline for greater than 1000 (TBD) sessions is frozen. In order to reclaim its stake, the node must first reactivate itself by going online.

## Rewards

### Vesting Schedule

Rewards are distributed based on a vesting schedule. When a request is added to the ingestion queue by a data owner, the price for the gateway node is locked and the data owner locks that amount of currency within a vesting schedule. 

wishful thinking: The 50% of the total is distributed after an asset class is created
over the next 50 blocks, the other 50% is leaked to the gateway, 1% per block.

## Slashing

We use a slashing mechanism to discourage poor behavior. Further, this mechanism punishes nodes who do not properly proxy requests to the underlying ipfs node. To be explicity, we slash funds based on:

* time to process requests: if a live proxy doesn't respond from a request to execute an ipfs function, we slash based on the amount of time that they have exceeded. If they never respond but remain online, we continue slashing until their staked amount falls under the minimum stake amount, after which they are marked ineligible.

## Election Algorithm

The election algorithm currently in use is described [here](./node_election.md).
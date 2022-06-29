# Authorization

This pallet allows a rule executor to be associated with an asset class and allows for that rule executor to submit results on chain in order to grant or deny data authorization to specific addresses.

## Locking Mechanism

All data locked or unlocked by a rule executor is found in the `Lock` storage double map. This runtime storage map associates a rule executor address and consumer address combination with a vector of asset ids which are associated with a boolean status, where true implies that the data is currently unlocked for the consumer and false implies that it is locked.

When data is unlocked, it is implicitly loaded into hot storage and delivered to the consumer. Unlocked data is locked again after one session passes.

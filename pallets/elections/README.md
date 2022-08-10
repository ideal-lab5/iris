# Elections Pallet

## Goal
The Elections module conducts and manages elections that determine which gateway/proxy nodes are responsible for processing requests in the ingestion and ejections queues.

### Election Process 

The election process is as follows. There are three major phases to the process, the request creation phase, the stake redistribution phase, and finally the results phase. For the following, we will find it convenient to assume that we start some arbitrary block `0`. Also, assume that we have integers $L, M > 0$.

#### Request Creation Phase
This phase is active from block `0` to block `L`. In this initial phase, nodes submit requests to the `pending ingestion request queue`. 

#### Stake Redistribution Phase
This phase is active from block `L+1` to block `L+M+1`. At the beginning of this phase, we copy all requests added to the queue in the previous stage and insert them into the `active ingestion request queue`. That is, the `active ingestion request queue` contains all ingestion requests added to the `pending ingestion request queue` between blocks `0` and `L`. Subsequently, the ingestion queue is cleared and this process is restarted. That is, we begin to repopulate the ingestion queue and we never have any instances where the ingestion queue itself is unavailable. Note that this means the choices of L, M, and N are very important.

Now that we have a static set of ingestion requests, over the duration of the next `N` blocks, eligible gateway/proxy nodes are responsible for redistributing their stake among the items in the ingestion queue. This is handled with the offchain client, which calls an extrinsic with the stake redistribution specified.

#### Results/Processing Phase
This phase is active from block `L+M+2` to whenever all commands in the queue have been processed.
This stage begins by recording the results of the election into a queryable election results map which is shared with other modules via the ElectionsProvider trait. Items are removed only when a node submits some proof of execution back to the elections module via the `xyz` extrinsic.

NOTE: FOR THE TIME BEING this doesn't really rely on consensus, it's really the first node wins. That is, the fastest nodes gets to decide the windows technically. I think I need to do some more research into how this should properly function.

*note: we still need to consider the case where there are multiple winners.*

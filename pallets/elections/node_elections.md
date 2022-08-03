# Node Elections

This document outlines how we elect which proxy nodes can process specific requests added to the IngestionQueue and the EjectionQueue. In the following, we construst a mathematical model of the proxy node elections.

Let $P = \{p_i\}_{i=0}^n$ be the set of proxy nodes during some session $s$, where each proxy node can be considered as the tuple $p_i = (s_i, \sigma_i, \delta_i)$, where:

- $s_i$ is the current stake of the node
- $\sigma_i$ is the current available storage capacity
- $\delta_i$ is the reported maximum bandwidth that the node is willing to handle

Further, assume that for some amount of data, say $d$ mb, we want to be able to process it in a minimum of $\epsilon$ seconds. (note: we use $\epsilon$ to infer that this amount of time should be as small as possible).

## Overview

Each proxy node will be given an opportunity to vote on which requests they want to proxy. They do this by ranking items in the ingestion queue using an ROI-optimizing algorithm. Subsequently, they use their staked IRIS to place votes on each of the selected items. After all votes are places and gossiped to peers, the node with the highest stake for any given request is deemed the winner of the election for that request, and thus is able to proxy the request.

## Ingestion Queue

For now, we reduce our treatment to requests in the ingestion queue, $I = \{I_k\}_{k=0}^m$ where $\forall i \in I, i = (\alpha, \beta)$ where $\alpha$ is the *estimated* amount of data (in gb) that must be transferred and $\beta$ is the amount of IRIS the the originator of the request has reserved to pay the proxy who takes the request.

### Ingestion Queue Voting Phase

Choose some proxy node $p \in P$ with $p = (\sigma_p, \delta_p)$.

1. FIlter the ingestion queue to get a collection that contains all potential subsets that $p$ can process. That is, the collection whose estimated size in gb is less than the available capacity of $p$, $\sigma_p$. This subset is given by: $I_{\lt \sigma_p} = \{i \in I : i.\alpha \lt \sigma_p \}$.
2. Our goal now is to find elements of $I_{\lt \sigma_p}$ that maximizes the total reserved balance, or rather, ROI.
   a. First we sort the collection be decreasing reserved balance,given by the set: $I_{\lt \sigma_p, \beta} = \{ i_j \in I : i_{j-1}.\beta \geq i_j.\beta \}$.
   b. Now we find the index $k \in [0, |I_{\lt \sigma_p, \beta}|]$ such that $\sum_{i=0}^k ([I_{\lt \sigma_p, \beta}]_i.\alpha) \lt \sigma_p$
3. Now we need to normalize the reserved balances and the amount that the proxy has staked so that we can assign votes to each chosen element. The total of all reserved balances in given by $\sum_{i=0}^k [I_{\lt \sigma_p, \beta}]_k.\beta$. Then, the amount of currency we stake for each vote is given by $\delta_p / \sum_{i=0}^k [I_{\lt \sigma_p, \beta}]_k.\beta$. And so, for each request $i_j$ the node wants to proxy, a vote is placed with a weight $\beta_j \sigma_p / \sum_{i=0}^k [I_{\lt \sigma_p, \beta}]_k.\beta $

### Ingestion Queue Ballot Tallying Phase

Finally, each proxy node $p$ gossips its votes with the rest of the network. Each node aggregates votes and the node with the greatest balance staked for any specific command is the winner. 

#### Tie Breakers



## Ejection Queue

The ejection queue functions quite differently than the ingestion queue. The commands that exist within this queue do not indicate an estimated amount of data that will be transferred, and this knowledge is only known after a proxy node is selected and is able to query the ipfs node to determine the real size of the data.

### Algorithm

TODO

## Ingestion and Ejection Queue Command Priorities

TODO
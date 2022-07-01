# Node Elections

This document outlines how we elect which proxy nodes can process specific requests added to the IngestionQueue and the EjectionQueue. In the following, we construst a mathematical model of the proxy node elections.

Let $P = \{p_i\}_{i=0}^n$ be the set of proxy nodes during some session $s$, where each proxy node can be considered as the tuple $p_i = (s_i, a_i, b_i)$, where:

- $s_i$ is the current stake of the node
- $a_i$ is the current available storage capacity
- $b_i$ is the reported maximum bandwidth that the node is willing to handle

Further, assume that for some amount of data, say $d$ mb, we want to be able to process it in a minimum of $\epsilon$ seconds. (note: we use $\epsilon$ to infer that this amount of time should be as small as possible).

Let $in_s$ represent the ingestion queue and $out_s$ represent the ejection queue for the current session $s$.

## Ingestion Queue

For now, we reduce our treatment to only the ingestion queue, say $I = \{I_k\}_{k=0}^m$ where $\forall i \in I, i = (d, r)$ where $d$ is the *estimated* amount of data in mb that must be transferred and $r$ is the amount of IRIS the the originator of the request has reserved to pay the proxy who takes the request.

We also assume that each proxy node $p_i$ has its own personal "price curve" which is defined by $p_i(x) = {\aa x \over \delta_i - x} + p$ where $\aa$ is a curve multiplier and $p$ is a minimum price and both are constants agreed on via governance, $\delta_i$ is the total storage capacity of the node and $x$ is the total size of the data that must be transferred through the network.

### The algorithm

For the following, we outline the case where we only consider bandwidth as a factor when assigned requests to proxies.

1. **SORT**: Sort the queue $I$ such that the amount of data to be transferred is monotonically increasing. That is, we create $I'$ where $d_{k} \leq d_{k+1}$ and $r_k \leq r_{k+1}$.

2. **CHOOSE**: Choose the terminal element $i_m \in I'$.

3. **FILTER BASED ON TOTAL BANDWIDTH**: Find the subset $P_m \subseteq P$ such that $p \in P_m \iff b \geq d_m$, where $d_m$ is the amount of data to be transferred by executing the command $i_m$.

4. **FILTER  BASED ON BANDWIDTH AND SPEED**: Find the subset $P_m' \subseteq P_m$ such that $P_m' = \{ p \in P_m | b * d_m \leq \epsilon \}$. That is, the subset of $P_m$ that is (reportedly) capable of transferring the data within the maximum allowed time.

5. **FILTER BASED ON COST OF STORAGE**: Find the subset $P_m'' \subseteq P_m'$ such that $P_m'' = \{p \in P_m' | p(d_m) \leq r_m\}$.

6. **CHOOSE**: At random, choose some $p \in P_m'$ to proxy the request $i_m$ and gossip the selection to the rest of the network.

7. **GOSSIP**: Update the amount of remaining bandwidth that the chosen $p$ can handle in the next selection and remove $i_m$ from the queue.

8. **ITERATE**: Continue this process until there are no remaining commands in the queue. If there are any commands that cannot be assigned, they roll over to the next session with high priority.

## Ejection Queue

The ejection queue functions quite differently than the ingestion queue. The commands that exist within this queue do not indicate an estimated amount of data that will be transferred, and this knowledge is only known after a proxy node is selected and is able to query the ipfs node to determine the real size of the data.

### Algorithm

TODO

## Ingestion and Ejection Queue Command Priorities

TODO
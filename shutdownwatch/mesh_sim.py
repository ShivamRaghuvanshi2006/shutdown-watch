"""Delay-tolerant messaging simulator.

Phones move around randomly. When two come within radio range they swap the
messages they carry ("epidemic routing"). We compare that with a baseline where
a message is only delivered if the sender physically meets the recipient.
"""
import random
from dataclasses import dataclass, field


@dataclass
class Node:
    id: int
    x: float
    y: float
    buf: set = field(default_factory=set)


def simulate(n_nodes=30, area=100.0, radius=15.0, steps=300, n_msgs=10,
             ttl=200, mode="epidemic", seed=1, step_size=5.0):
    rng = random.Random(seed)
    nodes = [Node(i, rng.uniform(0, area), rng.uniform(0, area)) for i in range(n_nodes)]
    msgs = {}
    for m in range(n_msgs):
        src, dst = rng.sample(range(n_nodes), 2)
        msgs[m] = (src, dst)
        nodes[src].buf.add(m)

    delivered, copies_sent = {}, 0
    for t in range(1, steps + 1):
        for nd in nodes:
            nd.x = min(area, max(0.0, nd.x + rng.uniform(-step_size, step_size)))
            nd.y = min(area, max(0.0, nd.y + rng.uniform(-step_size, step_size)))
        if t > ttl:  # messages created at t=0 all expire together
            break
        for i in range(n_nodes):
            for j in range(i + 1, n_nodes):
                a, b = nodes[i], nodes[j]
                if (a.x - b.x) ** 2 + (a.y - b.y) ** 2 > radius ** 2:
                    continue
                for src_n, dst_n in ((a, b), (b, a)):
                    for m in list(src_n.buf):
                        if m in dst_n.buf:
                            continue
                        _, dest = msgs[m]
                        if mode == "direct" and dst_n.id != dest:
                            continue  # baseline: only hand over to the final recipient
                        dst_n.buf.add(m)
                        copies_sent += 1
                        if dst_n.id == dest and m not in delivered:
                            delivered[m] = t

    n_del = len(delivered)
    return {
        "mode": mode,
        "delivery_ratio": round(n_del / n_msgs, 2),
        "avg_latency_steps": round(sum(delivered.values()) / n_del, 1) if n_del else None,
        "transmissions": copies_sent,
    }

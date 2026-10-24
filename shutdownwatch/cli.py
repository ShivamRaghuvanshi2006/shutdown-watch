import argparse
import json
from dataclasses import asdict

from . import analyze, mesh_sim, probes


def cmd_scan(args):
    with open(args.targets) as f:
        hosts = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    results = []
    for h in hosts:
        r = probes.probe(h, control_dns=args.control_dns, timeout=args.timeout)
        results.append(r)
        print(f"{h:28} {analyze.classify(r)}")
    overall, verdicts = analyze.summarize(results)
    print(f"\noverall: {overall}")
    if args.out:
        with open(args.out, "w") as f:
            json.dump({"overall": overall, "verdicts": verdicts,
                       "raw": [asdict(r) for r in results]}, f, indent=2)
        print(f"saved {args.out}")


def cmd_mesh(args):
    for mode in ("direct", "epidemic"):
        res = mesh_sim.simulate(n_nodes=args.nodes, radius=args.radius, steps=args.steps,
                                n_msgs=args.msgs, ttl=args.steps, mode=mode, seed=args.seed)
        print(res)


def main(argv=None):
    p = argparse.ArgumentParser(prog="shutdownwatch")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="probe sites layer by layer and classify blocking")
    s.add_argument("--targets", default="data/targets.txt")
    s.add_argument("--control-dns", default="8.8.8.8")
    s.add_argument("--timeout", type=float, default=5.0)
    s.add_argument("--out")
    s.set_defaults(func=cmd_scan)

    m = sub.add_parser("mesh", help="simulate store-and-forward messaging")
    m.add_argument("--nodes", type=int, default=30)
    m.add_argument("--radius", type=float, default=15.0)
    m.add_argument("--steps", type=int, default=300)
    m.add_argument("--msgs", type=int, default=10)
    m.add_argument("--seed", type=int, default=1)
    m.set_defaults(func=cmd_mesh)

    args = p.parse_args(argv)
    args.func(args)

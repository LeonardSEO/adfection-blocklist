#!/usr/bin/env python3
"""Trusted offline publisher: merge evidence, evaluate qualified rules, validate output."""
import argparse
import pathlib
from research import ROOT, read_json, write_json, merge_measurements, reconcile, validate_registry, utcnow


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--measurements', type=pathlib.Path)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    registry = read_json(ROOT / 'research/registry.json')
    rules = read_json(ROOT / 'research/detectors.json')['detectors']
    bootstrap = read_json(ROOT / 'sources/bootstrap.json')
    if args.measurements:
        registry = merge_measurements(registry, read_json(args.measurements / 'research/registry.json'))
    if args.check:
        validate_registry(registry, rules, bootstrap)
    else:
        reconcile(registry, rules, utcnow())
        validate_registry(registry, rules, bootstrap)
        write_json(ROOT / 'research/registry.json', registry)
        if args.measurements:
            report = read_json(args.measurements / 'candidates/latest.json')
            # Keep status reporting as data; it is not input to indicator admission.
            write_json(ROOT / 'candidates/latest.json', report)
    counts = {s: sum(r['status'] == s for r in registry['indicators'].values()) for s in ('historical', 'candidate', 'accepted', 'withdrawn')}
    print(counts)


if __name__ == '__main__':
    main()

#!/usr/bin/python3
"""Bounded, streaming replay benchmark. Includes file parsing and analysis."""
import argparse
import dataclasses
import json
import resource
import statistics
import time
from netlab.analyze.engine import AnalysisEngine
from netlab.capture.pcapio import iter_capture_file
from netlab.config import Config
from netlab.util.bounded import DropCountingQueue
p = argparse.ArgumentParser()
p.add_argument('capture')
p.add_argument('--runs', type=int, default=5)
args = p.parse_args()
rates = []
for _ in range(args.runs):
    engine = AnalysisEngine(DropCountingQueue(1000), Config())
    start = time.perf_counter()
    batch = []
    for packet in iter_capture_file(args.capture):
        batch.append(packet)
        if len(batch) >= 1024:
            engine.ingest_batch(batch); batch.clear()
    engine.ingest_batch(batch)
    elapsed = time.perf_counter() - start
    st = engine.stats()
    rates.append(st.total_packets / elapsed)
print(json.dumps(dict(capture=args.capture, runs=args.runs,
    median_packets_per_second=statistics.median(rates), rates=rates,
    max_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    stats=dataclasses.asdict(st)), indent=2))

# Benchmarks

Benchmarks compare pattrie against [pytricia](https://github.com/jsommers/pytricia) using [pytest-benchmark](https://pytest-benchmark.readthedocs.io/).

## Setup

```bash
uv run maturin develop --release
uv run pytest benches/bench.py --benchmark-only -v
```

## Baseline results

Measured on Apple M-series, release build, 100 000 random prefixes / 100 000 random IPs.

| Benchmark | pattrie | pytricia | ratio |
|-----------|---------|----------|-------|
| build (insert 100k prefixes) | ~29 ms | ~32 ms | 0.91× |
| LPM lookup (100k IPs) | ~36 ms | ~40 ms | 0.90× |
| LPM lookup – frozen (GIL-free) | ~36 ms | — | — |
| iteration (100k keys) | ~10 ms | ~14 ms | 0.71× |

`frozen` mode releases the GIL during trie traversal, enabling true concurrent reads from multiple threads at no single-threaded cost.

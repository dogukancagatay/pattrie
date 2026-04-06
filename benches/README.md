# Benchmarks

Benchmarks compare pattrie against [pytricia](https://github.com/jsommers/pytricia) and [pysubnettree](https://github.com/zeek/pysubnettree) using [pytest-benchmark](https://pytest-benchmark.readthedocs.io/).

## Setup

```bash
uv run maturin develop --release
uv run pytest benches/bench.py --benchmark-only -v
```

Optional dependencies (benchmarks skip gracefully if not installed):

```bash
uv sync --dev  # installs pytricia and pysubnettree
```

## Baseline results

Measured on Apple M-series, Python 3.13, release build, 100 000 random prefixes / 100 000 random IPs.

| Benchmark | pattrie | pattrie (frozen) | pytricia | pysubnettree |
|-----------|---------|-----------------|----------|--------------|
| build (insert 100k prefixes) | ~27 ms | — | ~35 ms | ~62 ms |
| LPM lookup (100k IPs) | ~39 ms | ~38 ms | ~46 ms | ~57 ms |
| iteration (100k keys) | ~11 ms | — | ~16 ms | ~33 ms |

`frozen` mode releases the GIL during trie traversal, enabling true concurrent reads from multiple threads at no single-threaded cost.

## Batch lookup (pattrie only)

`get_many(keys)` processes a list of keys in a single Python→Rust call, eliminating per-call overhead. In frozen mode the entire traversal phase runs without the GIL.

| Benchmark | pattrie | pattrie (frozen) |
|-----------|---------|-----------------|
| get_many (100k IPs) | ~31 ms | ~49 ms |

> Batch results are not directly comparable to the single-key table above — pytricia and pysubnettree have no equivalent batch API.

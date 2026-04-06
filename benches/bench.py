import socket
import random
import pytest
import pattrie

try:
    import pytricia
    HAS_PYTRICIA = True
except ImportError:
    HAS_PYTRICIA = False


def _random_prefixes(n: int) -> list[str]:
    prefixes: set[str] = set()
    while len(prefixes) < n:
        a, b = random.randint(0, 255), random.randint(0, 255)
        plen = random.choice([8, 16, 24])
        prefixes.add(f"{a}.{b}.0.0/{plen}")
    return list(prefixes)


def _random_ips(n: int) -> list[str]:
    return [
        f"{random.randint(0,255)}.{random.randint(0,255)}"
        f".{random.randint(0,255)}.{random.randint(0,255)}"
        for _ in range(n)
    ]


PREFIXES_100K = _random_prefixes(100_000)
IPS_100K = _random_ips(100_000)


@pytest.fixture
def pattrie_trie_100k():
    t = pattrie.Pattrie()
    for i, p in enumerate(PREFIXES_100K):
        t[p] = i
    return t


@pytest.fixture
def pytricia_trie_100k():
    if not HAS_PYTRICIA:
        pytest.skip("pytricia not installed")
    t = pytricia.PyTricia()
    for i, p in enumerate(PREFIXES_100K):
        t[p] = i
    return t


def test_bench_build_pattrie(benchmark):
    def build():
        t = pattrie.Pattrie()
        for i, p in enumerate(PREFIXES_100K):
            t[p] = i
    benchmark(build)


def test_bench_build_pytricia(benchmark):
    if not HAS_PYTRICIA:
        pytest.skip("pytricia not installed")

    def build():
        t = pytricia.PyTricia()
        for i, p in enumerate(PREFIXES_100K):
            t[p] = i
    benchmark(build)


def test_bench_lpm_pattrie(benchmark, pattrie_trie_100k):
    t = pattrie_trie_100k

    def lookup():
        for ip in IPS_100K:
            t.get(ip)
    benchmark(lookup)


def test_bench_lpm_pytricia(benchmark, pytricia_trie_100k):
    t = pytricia_trie_100k

    def lookup():
        for ip in IPS_100K:
            t.get(ip)
    benchmark(lookup)


def test_bench_lpm_frozen_pattrie(benchmark, pattrie_trie_100k):
    """Frozen trie: GIL released during trie traversal."""
    t = pattrie_trie_100k
    t.freeze()

    def lookup():
        for ip in IPS_100K:
            t.get(ip)
    benchmark(lookup)


def test_bench_iter_pattrie(benchmark, pattrie_trie_100k):
    def iterate():
        list(pattrie_trie_100k)
    benchmark(iterate)


def test_bench_iter_pytricia(benchmark, pytricia_trie_100k):
    def iterate():
        list(pytricia_trie_100k)
    benchmark(iterate)

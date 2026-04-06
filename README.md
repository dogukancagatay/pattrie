# Pattrie

Fast IP prefix trie for Python with a Rust backend. Supports longest-prefix match (LPM) lookups on IPv4 and IPv6 networks.

Built with [PyO3](https://pyo3.rs) and the [`prefix-trie`](https://crates.io/crates/prefix-trie) crate. Inspired by [pytricia](https://github.com/jsommers/pytricia).

## Installation

```bash
pip install pattrie
```

## Usage

```python
import pattrie

t = pattrie.Pattrie()
t["10.0.0.0/8"] = "rfc1918"
t["10.1.0.0/16"] = "internal"

t["10.1.2.3"]          # "internal"      (LPM)
t["10.2.0.1"]          # "rfc1918"       (LPM)
"10.1.2.3" in t        # True
t.get_key("10.1.2.3")  # "10.1.0.0/16"
t.get("192.0.2.1")     # None
```

Keys can be strings, `ipaddress.IPv4Address`, `IPv4Network`, `IPv6Address`, or `IPv6Network`.

### IPv6

```python
import socket
import pattrie

t = pattrie.Pattrie(128, socket.AF_INET6)
t["2001:db8::/32"] = "documentation"
t["fe80::/10"] = "link-local"

t["fe80::1"]  # "link-local"
```

### Concurrent reads with `freeze()`

After `freeze()`, read operations release the GIL, allowing true parallel lookups from multiple threads:

```python
t = pattrie.Pattrie()
# ... populate ...
t.freeze()  # trie becomes read-only; reads release the GIL

# Safe to call from many threads simultaneously
value = t["10.1.2.3"]

t.thaw()    # restore mutability
```

## API

```python
class Pattrie:
    def __init__(self, maxbits: int = 32, family: int = socket.AF_INET) -> None: ...

    # Insert
    def insert(self, prefix: str | IPv4Network | IPv6Network, value: object) -> None: ...
    def insert(self, addr: str | IPv4Address | IPv6Address, prefixlen: int, value: object) -> None: ...
    def __setitem__(self, key: str | IPv4Network | IPv6Network, value: object) -> None: ...

    # Lookup (LPM)
    def __getitem__(self, key: str | IPv4Address | IPv6Address | IPv4Network | IPv6Network) -> object: ...
    def get(self, key, default=None) -> object: ...
    def get_key(self, key) -> str | None: ...
    def __contains__(self, key) -> bool: ...

    # Exact match
    def has_key(self, key: str | IPv4Network | IPv6Network) -> bool: ...

    # Delete
    def __delitem__(self, key: str | IPv4Network | IPv6Network) -> None: ...
    def delete(self, key: str | IPv4Network | IPv6Network) -> None: ...

    # Iteration
    def __iter__(self) -> Iterator[str]: ...
    def keys(self) -> list[str]: ...
    def __len__(self) -> int: ...

    # Concurrency
    def freeze(self) -> None: ...
    def thaw(self) -> None: ...
```

## Performance

See [`benches/README.md`](benches/README.md) for methodology and numbers.

## License

MIT — see [LICENSE](LICENSE).

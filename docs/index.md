# Pattrie

Fast IP prefix trie for Python with a Rust backend. Supports longest-prefix match (LPM) lookups on IPv4 and IPv6 networks.

Built with [PyO3](https://pyo3.rs) and the [`prefix-trie`](https://crates.io/crates/prefix-trie) crate.

## Installation

```bash
pip install pattrie
```

## Quick Start

```python
import pattrie

t = pattrie.Pattrie()
t["10.0.0.0/8"] = "rfc1918"
t["10.1.0.0/16"] = "internal"

t["10.1.2.3"]          # "internal"  (longest-prefix match)
t["10.2.0.1"]          # "rfc1918"
"10.1.2.3" in t        # True
t.get_key("10.1.2.3")  # "10.1.0.0/16"
t.get("192.0.2.1")     # None
```

Keys can be strings, `ipaddress.IPv4Address`, `IPv4Network`, `IPv6Address`, or `IPv6Network`.

## IPv6

```python
import socket
import pattrie

t = pattrie.Pattrie(128, socket.AF_INET6)
t["2001:db8::/32"] = "documentation"
t["fe80::/10"] = "link-local"

t["fe80::1"]  # "link-local"
```

## Concurrent Reads with `freeze()`

After `freeze()`, read operations release the GIL, allowing true parallel lookups from multiple threads:

```python
t = pattrie.Pattrie()
# ... populate ...
t.freeze()  # trie becomes read-only; reads release the GIL

# Safe to call from many threads simultaneously
value = t["10.1.2.3"]

t.thaw()    # restore mutability
```

## Cross-Process Sharing with `dump()` / `load()`

Serialize a frozen trie to a binary file and load it back in another process:

```python
# Writer process
t = pattrie.Pattrie()
t["10.0.0.0/8"] = "rfc1918"
t.freeze()
t.dump("routes.ptri")

# Reader process
t2 = pattrie.Pattrie.load("routes.ptri")
t2["10.1.2.3"]  # "rfc1918"
```

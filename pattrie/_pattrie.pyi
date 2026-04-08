import os
import socket
from collections.abc import Iterator, Sequence
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Self, final, overload

__all__ = ["Pattrie"]

type NetworkKey = str | IPv4Network | IPv6Network
type AddressKey = str | int | IPv4Address | IPv6Address | IPv4Network | IPv6Network

@final
class Pattrie:
    """A longest-prefix-match (LPM) IP prefix trie.

    Stores arbitrary Python values keyed by IP prefixes. Lookups return
    the value associated with the *longest* matching prefix.

    Args:
        maxbits: Maximum prefix length accepted (1–32 for IPv4, 1–128 for
            IPv6). Defaults to 32.
        family: Address family — `socket.AF_INET` (default) or
            `socket.AF_INET6`.

    Raises:
        ValueError: If `family` is not `AF_INET` or `AF_INET6`, or if
            `maxbits` is out of range for the chosen family.

    Example:
        ```python
        import pattrie

        t = pattrie.Pattrie()
        t["10.0.0.0/8"] = "rfc1918"
        t["10.1.0.0/16"] = "internal"

        t["10.1.2.3"]  # → "internal"  (longest match wins)
        t["10.2.0.1"]  # → "rfc1918"
        ```
    """

    def __new__(
        cls,
        maxbits: int = 32,
        family: int = socket.AF_INET,
    ) -> Self: ...
    @overload
    def insert(self, prefix: NetworkKey, value: object) -> None:
        """Insert a prefix and its associated value.

        Accepts two calling conventions:

        - `insert(prefix, value)` — `prefix` is a string, `IPv4Network`, or
          `IPv6Network`. Host bits are zeroed before insertion.
        - `insert(addr, prefixlen, value)` — address and prefix length given
          separately.

        Raises:
            ValueError: If the trie is frozen, the prefix is malformed, the
                prefix length exceeds `maxbits`, or there is an
                address-family mismatch.
        """
        ...
    @overload
    def insert(self, addr: AddressKey, prefixlen: int, value: object) -> None: ...
    def __setitem__(self, key: NetworkKey, value: object, /) -> None:
        """Insert or replace a prefix using `t[prefix] = value`.

        Equivalent to `insert(prefix, value)`. Host bits are zeroed before
        insertion (`"10.1.2.3/8"` is stored as `"10.0.0.0/8"`).

        Raises:
            ValueError: If the trie is frozen or the prefix is invalid.
        """
        ...

    def __getitem__(self, key: AddressKey, /) -> object:
        """Longest-prefix-match lookup using `t[key]`.

        Returns the value stored for the longest matching prefix.

        Args:
            key: An IP address or network prefix (string, `IPv4Address`,
                `IPv6Address`, `IPv4Network`, or `IPv6Network`).

        Returns:
            The value for the longest matching prefix.

        Raises:
            KeyError: If no prefix in the trie covers `key`.
        """
        ...

    def __delitem__(self, key: NetworkKey, /) -> None:
        """Delete a prefix using `del t[prefix]`.

        Requires an exact match. Host bits are zeroed before lookup.

        Raises:
            KeyError: If the prefix is not in the trie.
            ValueError: If the trie is frozen or the prefix is invalid.
        """
        ...

    def __contains__(self, key: AddressKey, /) -> bool:
        """Return `True` if any prefix in the trie covers `key` (LPM semantics).

        Does not raise on invalid or unrecognised keys — returns `False`
        instead.
        """
        ...

    def __len__(self) -> int:
        """Return the number of prefixes stored in the trie."""
        ...

    def __iter__(self) -> Iterator[str]:
        """Iterate over all stored prefixes as CIDR strings."""
        ...

    def get(self, key: AddressKey, default: object = None) -> object:
        """Longest-prefix-match lookup, returning `default` on a miss.

        Args:
            key: An IP address or network prefix.
            default: Value to return when no prefix matches. Defaults to
                `None`.

        Returns:
            The matched value, or `default`.
        """
        ...

    def get_many(self, keys: Sequence[AddressKey], default: object = None) -> list[object]:
        """Look up multiple keys in one call, returning a list of values.

        Each key is resolved by longest-prefix match; misses return `default`.
        When the trie is frozen, all trie traversals run without the GIL,
        enabling true parallel use from multiple threads.

        Args:
            keys: A sequence of IP addresses or network prefixes.
            default: Value to return for each miss. Defaults to `None`.

        Returns:
            A list of matched values (or `default`) in the same order as
            `keys`.
        """
        ...

    def get_key(self, key: AddressKey) -> str | None:
        """Return the matching prefix for a longest-prefix-match lookup.

        Unlike `__getitem__`, returns the *prefix string* (e.g.
        `"10.0.0.0/8"`) rather than the stored value.

        Args:
            key: An IP address or network prefix.

        Returns:
            The matched prefix as a CIDR string, or `None` on a miss.
        """
        ...

    def has_key(self, key: NetworkKey) -> bool:
        """Return `True` if `key` is an *exact* prefix in the trie.

        Unlike `__contains__`, this requires an exact match — no
        longest-prefix semantics.

        Args:
            key: A network prefix (string, `IPv4Network`, or `IPv6Network`).

        Returns:
            `True` if the exact prefix exists, `False` otherwise.
        """
        ...

    def delete(self, key: NetworkKey) -> None:
        """Delete an exact prefix from the trie.

        Equivalent to `del t[prefix]`. Host bits are zeroed before lookup.

        Raises:
            KeyError: If the prefix is not in the trie.
            ValueError: If the trie is frozen or the prefix is invalid.
        """
        ...

    def keys(self) -> list[str]:
        """Return a list of all stored prefixes as CIDR strings."""
        ...

    def children(self, prefix: NetworkKey) -> list[str]:
        """Return all prefixes in the trie more specific than ``prefix``.

        Uses longest-prefix containment: any stored prefix whose address
        range is entirely within ``prefix`` is included at any depth.
        The queried ``prefix`` itself is never included in the result.
        Returns ``[]`` when no descendants exist or the trie is empty.

        Args:
            prefix: The parent prefix to query (CIDR string, ``IPv4Network``,
                or ``IPv6Network``). Host bits are zeroed before lookup.

        Returns:
            A list of CIDR strings for all stored prefixes contained within
            ``prefix``. Order is lexicographic (prefix-trie traversal order).

        Raises:
            ValueError: If ``prefix`` belongs to the wrong address family or
                is malformed.

        Example:
            ```python
            t = Pattrie()
            t["10.0.0.0/8"] = "a"
            t["10.1.0.0/16"] = "b"
            t["10.1.1.0/24"] = "c"
            t["10.2.0.0/16"] = "d"

            t.children("10.0.0.0/8")
            # → ["10.1.0.0/16", "10.1.1.0/24", "10.2.0.0/16"]

            t.children("10.0.0.0/9")   # not stored — still returns descendants
            # → ["10.1.0.0/16", "10.1.1.0/24"]
            ```
        """
        ...

    def parent(self, prefix: NetworkKey) -> str | None:
        """Return the closest covering prefix for ``prefix``.

        Returns the longest stored prefix that contains ``prefix`` but is not
        ``prefix`` itself — i.e. the immediate ancestor in the stored prefix
        hierarchy. Returns ``None`` if no covering prefix exists.

        Args:
            prefix: The prefix to query (CIDR string, ``IPv4Network``, or
                ``IPv6Network``). Host bits are zeroed before lookup.

        Returns:
            The CIDR string of the longest stored prefix that covers
            ``prefix``, or ``None`` if no such prefix exists.

        Raises:
            ValueError: If ``prefix`` belongs to the wrong address family or
                is malformed.

        Example:
            ```python
            t = Pattrie()
            t["10.0.0.0/8"] = "a"
            t["10.1.0.0/16"] = "b"
            t["10.1.1.0/24"] = "c"

            t.parent("10.1.1.0/24")   # → "10.1.0.0/16"
            t.parent("10.1.0.0/16")   # → "10.0.0.0/8"
            t.parent("10.0.0.0/8")    # → None

            t.parent("10.2.0.0/16")   # → "10.0.0.0/8"  (not stored — still works)
            ```
        """
        ...

    def __getstate__(self) -> dict[str, object]: ...
    def __setstate__(self, state: dict[str, object]) -> None: ...
    def dump(self, path: str | os.PathLike[str]) -> None:
        """Serialize this frozen trie to a binary file.

        The file can be loaded in another process with `Pattrie.load()`.
        The trie must be frozen before calling this method.

        Args:
            path: Destination file path.

        Raises:
            ValueError: If the trie is not frozen or the file cannot be
                created.
        """
        ...

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> Pattrie:
        """Load a trie from a binary file written by `dump()`.

        Uses memory-mapped I/O for efficiency. The returned trie is frozen.

        Args:
            path: Path to a file written by `dump()`.

        Returns:
            A new frozen `Pattrie` instance.

        Raises:
            ValueError: If the file is not a valid pattrie dump or is
                corrupt.
        """
        ...

    def freeze(self) -> None:
        """Make the trie read-only and enable GIL-free concurrent reads.

        After freezing, `__getitem__`, `get`, `get_many`, and `__contains__`
        all release the GIL, allowing true parallel lookups from multiple
        threads. Any mutation attempt raises `ValueError`.

        Use `thaw()` to restore mutability.
        """
        ...

    def thaw(self) -> None:
        """Restore mutability after `freeze()`.

        Read operations will re-acquire the GIL. Mutations are allowed again.
        """
        ...

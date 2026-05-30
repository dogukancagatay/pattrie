import pickle
import socket
import struct

import pytest

from pattrie import Pattrie

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _frozen_ipv4(**entries) -> Pattrie:
    t = Pattrie()
    for prefix, value in entries.items():
        t[prefix] = value
    t.freeze()
    return t


def _frozen_ipv6(**entries) -> Pattrie:
    t = Pattrie(maxbits=128, family=socket.AF_INET6)
    for prefix, value in entries.items():
        t[prefix] = value
    t.freeze()
    return t


# ---------------------------------------------------------------------------
# Round-trip: IPv4
# ---------------------------------------------------------------------------


def test_ipv4_roundtrip_basic(tmp_path):
    path = tmp_path / "trie.ptri"
    t = _frozen_ipv4(**{"10.0.0.0/8": "rfc1918", "192.168.0.0/16": "home"})
    t.dump(path)

    t2 = Pattrie.load(path)
    assert t2["10.1.2.3"] == "rfc1918"
    assert t2["192.168.1.1"] == "home"
    assert len(t2) == 2


def test_ipv4_roundtrip_preserves_len(tmp_path):
    path = tmp_path / "trie.ptri"
    t = _frozen_ipv4(**{"1.0.0.0/8": 1, "2.0.0.0/8": 2, "3.0.0.0/8": 3})
    t.dump(path)

    t2 = Pattrie.load(path)
    assert len(t2) == 3


def test_ipv4_roundtrip_loaded_trie_is_frozen(tmp_path):
    path = tmp_path / "trie.ptri"
    t = _frozen_ipv4(**{"10.0.0.0/8": "val"})
    t.dump(path)

    t2 = Pattrie.load(path)
    with pytest.raises(ValueError):
        t2["1.0.0.0/8"] = "new"


def test_ipv4_roundtrip_non_string_values(tmp_path):
    path = tmp_path / "trie.ptri"
    t = _frozen_ipv4(**{"10.0.0.0/8": {"asn": 64512, "tags": ["private"]}})
    t.dump(path)

    t2 = Pattrie.load(path)
    assert t2["10.1.1.1"] == {"asn": 64512, "tags": ["private"]}


def test_ipv4_roundtrip_none_value(tmp_path):
    path = tmp_path / "trie.ptri"
    t = _frozen_ipv4(**{"10.0.0.0/8": None})
    t.dump(path)

    t2 = Pattrie.load(path)
    assert t2["10.1.1.1"] is None


# ---------------------------------------------------------------------------
# Round-trip: IPv6
# ---------------------------------------------------------------------------


def test_ipv6_roundtrip_basic(tmp_path):
    path = tmp_path / "trie6.ptri"
    t = _frozen_ipv6(**{"2001:db8::/32": "documentation", "::1/128": "loopback"})
    t.dump(path)

    t2 = Pattrie.load(path)
    assert t2["2001:db8::1"] == "documentation"
    assert t2["::1"] == "loopback"
    assert len(t2) == 2


def test_ipv6_roundtrip_preserves_len(tmp_path):
    path = tmp_path / "trie6.ptri"
    t = _frozen_ipv6(**{"2001:db8::/32": 1, "fc00::/7": 2})
    t.dump(path)

    t2 = Pattrie.load(path)
    assert len(t2) == 2


# ---------------------------------------------------------------------------
# Empty-trie round-trip
# ---------------------------------------------------------------------------


def test_empty_ipv4_roundtrip(tmp_path):
    path = tmp_path / "empty.ptri"
    t = Pattrie()
    t.freeze()
    t.dump(path)

    t2 = Pattrie.load(path)
    assert len(t2) == 0


def test_empty_ipv6_roundtrip(tmp_path):
    path = tmp_path / "empty6.ptri"
    t = Pattrie(maxbits=128, family=socket.AF_INET6)
    t.freeze()
    t.dump(path)

    t2 = Pattrie.load(path)
    assert len(t2) == 0


# ---------------------------------------------------------------------------
# dump() requires frozen trie
# ---------------------------------------------------------------------------


def test_dump_requires_frozen(tmp_path):
    path = tmp_path / "trie.ptri"
    t = Pattrie()
    t["10.0.0.0/8"] = "val"
    with pytest.raises(ValueError, match="freeze"):
        t.dump(path)


# ---------------------------------------------------------------------------
# Corrupt / truncated file handling
# ---------------------------------------------------------------------------


def test_load_bad_magic(tmp_path):
    path = tmp_path / "bad.ptri"
    path.write_bytes(b"XXXX" + b"\x00" * 28)
    with pytest.raises(ValueError, match="magic|pattrie dump"):
        Pattrie.load(path)


def test_load_file_too_small(tmp_path):
    path = tmp_path / "tiny.ptri"
    path.write_bytes(b"PTRI\x01\x00\x00\x00")  # only 8 bytes
    with pytest.raises(ValueError, match="small|valid"):
        Pattrie.load(path)


def test_load_unsupported_version(tmp_path):
    path = tmp_path / "v99.ptri"
    af_inet = socket.AF_INET
    header = (
        b"PTRI"
        + struct.pack("<I", 99)  # version = 99
        + struct.pack("<I", af_inet)
        + struct.pack("<I", 32)  # maxbits
        + struct.pack("<Q", 0)  # entry_count
        + struct.pack("<Q", 32)  # values_offset
    )
    path.write_bytes(header)
    with pytest.raises(ValueError, match="[Vv]ersion"):
        Pattrie.load(path)


def test_load_truncated_entries(tmp_path):
    """File has entry_count=5 but entries section is too short."""
    path = tmp_path / "trunc.ptri"
    af_inet = socket.AF_INET
    entry_count = 5
    # Claim 5 entries but provide 0 bytes of entry data
    wrong_offset = 32 + entry_count * 5  # what it should be
    header = (
        b"PTRI"
        + struct.pack("<I", 1)
        + struct.pack("<I", af_inet)
        + struct.pack("<I", 32)
        + struct.pack("<Q", entry_count)
        + struct.pack("<Q", wrong_offset)
    )
    # Write header but no entries — file is only 32 bytes
    path.write_bytes(header)
    with pytest.raises(ValueError, match="[Cc]orrupt|offset"):
        Pattrie.load(path)


def test_load_bad_offsets(tmp_path):
    """values_offset field doesn't match computed offset."""
    path = tmp_path / "badoff.ptri"
    af_inet = socket.AF_INET
    pickled = pickle.dumps([])
    entry_count = 0
    wrong_offset = 99  # should be 32
    header = (
        b"PTRI"
        + struct.pack("<I", 1)
        + struct.pack("<I", af_inet)
        + struct.pack("<I", 32)
        + struct.pack("<Q", entry_count)
        + struct.pack("<Q", wrong_offset)
    )
    path.write_bytes(header + pickled)
    with pytest.raises(ValueError, match="[Cc]orrupt|offset"):
        Pattrie.load(path)

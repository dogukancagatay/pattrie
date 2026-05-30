"""Tests for set-like add() and discard() methods (issue #44)."""

import pickle
import socket
import tempfile
from pathlib import Path

import pytest

import pattrie

# ---------------------------------------------------------------------------
# add()
# ---------------------------------------------------------------------------


def test_add_basic_membership():
    t = pattrie.Pattrie()
    t.add("10.0.0.0/8")
    assert "10.1.2.3" in t
    assert t.has_key("10.0.0.0/8") is True


def test_add_returns_none():
    t = pattrie.Pattrie()
    assert t.add("10.0.0.0/8") is None


def test_add_value_is_none():
    t = pattrie.Pattrie()
    t.add("10.0.0.0/8")
    assert t["10.1.2.3"] is None
    assert t.get("10.1.2.3") is None


def test_add_values_yields_none():
    t = pattrie.Pattrie()
    t.add("10.0.0.0/8")
    t.add("192.168.0.0/16")
    assert t.values() == [None, None]


def test_add_items_yields_none_value():
    t = pattrie.Pattrie()
    t.add("10.0.0.0/8")
    items = t.items()
    assert items == [("10.0.0.0/8", None)]


def test_add_idempotent_no_error():
    t = pattrie.Pattrie()
    t.add("10.0.0.0/8")
    t.add("10.0.0.0/8")  # no-op, no exception
    assert len(t) == 1


def test_add_does_not_clobber_existing_value():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "important"
    t.add("10.0.0.0/8")  # must leave "important" intact
    assert t["10.0.0.0/8"] == "important"
    assert len(t) == 1


def test_setitem_after_add_upgrades_value():
    t = pattrie.Pattrie()
    t.add("10.0.0.0/8")
    t["10.0.0.0/8"] = "upgraded"
    assert t["10.0.0.0/8"] == "upgraded"


def test_add_frozen_raises():
    t = pattrie.Pattrie()
    t.freeze()
    with pytest.raises(ValueError):
        t.add("10.0.0.0/8")


def test_add_ipv4():
    t = pattrie.Pattrie()
    t.add("10.0.0.0/8")
    t.add("10.1.0.0/16")
    assert len(t) == 2
    assert "10.1.2.3" in t
    assert t.get_key("10.1.2.3") == "10.1.0.0/16"


def test_add_ipv6():
    t = pattrie.Pattrie(128, socket.AF_INET6)
    t.add("fe80::/32")
    t.add("2001:db8::/32")
    assert len(t) == 2
    assert "fe80::1" in t
    assert "2001:db8::1" in t
    assert t["fe80::1"] is None


def test_add_mixed_with_valued():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "valued"
    t.add("192.168.0.0/16")
    assert t["10.1.2.3"] == "valued"
    assert t["192.168.1.1"] is None
    assert len(t) == 2


def test_add_wrong_family_raises():
    t = pattrie.Pattrie(32, socket.AF_INET)
    with pytest.raises(ValueError):
        t.add("fe80::/32")


def test_add_malformed_raises():
    t = pattrie.Pattrie()
    with pytest.raises(ValueError):
        t.add("not-a-prefix")


def test_add_exceeds_maxbits_raises():
    t = pattrie.Pattrie(24)
    with pytest.raises(ValueError):
        t.add("10.0.0.0/25")


def test_add_respects_host_bit_zeroing():
    t = pattrie.Pattrie()
    t.add("10.1.2.3/8")  # host bits set — must be zeroed to 10.0.0.0/8
    assert t.has_key("10.0.0.0/8") is True
    assert t.has_key("10.1.2.3/8") is True  # same after zeroing


# ---------------------------------------------------------------------------
# discard()
# ---------------------------------------------------------------------------


def test_discard_removes_existing():
    t = pattrie.Pattrie()
    t.add("10.0.0.0/8")
    t.discard("10.0.0.0/8")
    assert len(t) == 0
    assert t.has_key("10.0.0.0/8") is False


def test_discard_absent_is_noop():
    t = pattrie.Pattrie()
    t.discard("10.0.0.0/8")  # no exception


def test_discard_returns_none():
    t = pattrie.Pattrie()
    t.add("10.0.0.0/8")
    assert t.discard("10.0.0.0/8") is None


def test_discard_valued_prefix():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "data"
    t.discard("10.0.0.0/8")
    assert len(t) == 0


def test_discard_frozen_raises():
    t = pattrie.Pattrie()
    t.add("10.0.0.0/8")
    t.freeze()
    with pytest.raises(ValueError):
        t.discard("10.0.0.0/8")


def test_discard_ipv6():
    t = pattrie.Pattrie(128, socket.AF_INET6)
    t.add("fe80::/32")
    t.discard("fe80::/32")
    assert len(t) == 0
    t.discard("fe80::/32")  # second discard is also a no-op


def test_discard_does_not_affect_siblings():
    t = pattrie.Pattrie()
    t.add("10.0.0.0/8")
    t.add("192.168.0.0/16")
    t.discard("10.0.0.0/8")
    assert len(t) == 1
    assert t.has_key("192.168.0.0/16") is True


def test_discard_malformed_raises():
    t = pattrie.Pattrie()
    with pytest.raises(ValueError):
        t.discard("not-a-prefix")


def test_discard_exceeds_maxbits_raises():
    t = pattrie.Pattrie(24)
    with pytest.raises(ValueError):
        t.discard("10.0.0.0/25")


# ---------------------------------------------------------------------------
# LPM / membership methods unaffected by valueless prefixes
# ---------------------------------------------------------------------------


def test_contains_valueless_prefix():
    t = pattrie.Pattrie()
    t.add("10.0.0.0/8")
    assert "10.1.2.3" in t
    assert "192.168.0.1" not in t


def test_get_key_valueless():
    t = pattrie.Pattrie()
    t.add("10.0.0.0/8")
    t.add("10.1.0.0/16")
    assert t.get_key("10.1.2.3") == "10.1.0.0/16"
    assert t.get_key("10.2.0.1") == "10.0.0.0/8"
    assert t.get_key("192.168.0.1") is None


def test_parent_valueless():
    t = pattrie.Pattrie()
    t.add("10.0.0.0/8")
    t.add("10.1.0.0/16")
    assert t.parent("10.1.0.0/16") == "10.0.0.0/8"
    assert t.parent("10.0.0.0/8") is None


def test_children_valueless():
    t = pattrie.Pattrie()
    t.add("10.0.0.0/8")
    t.add("10.1.0.0/16")
    t.add("10.2.0.0/16")
    result = sorted(t.children("10.0.0.0/8"))
    assert result == ["10.1.0.0/16", "10.2.0.0/16"]


def test_get_all_valueless():
    t = pattrie.Pattrie()
    t.add("10.0.0.0/8")
    t.add("10.1.0.0/16")
    result = t.get_all("10.1.2.3")
    assert result == [("10.1.0.0/16", None), ("10.0.0.0/8", None)]


def test_keys_valueless():
    t = pattrie.Pattrie()
    t.add("10.0.0.0/8")
    t.add("10.1.0.0/16")
    assert sorted(t.keys()) == ["10.0.0.0/8", "10.1.0.0/16"]


# ---------------------------------------------------------------------------
# get_many with valueless entries
# ---------------------------------------------------------------------------


def test_get_many_valueless_unfrozen():
    t = pattrie.Pattrie()
    t.add("10.0.0.0/8")
    t.add("192.168.0.0/16")
    result = t.get_many(["10.1.2.3", "192.168.1.1", "172.16.0.1"])
    assert result == [None, None, None]


def test_get_many_valueless_frozen():
    t = pattrie.Pattrie()
    t.add("10.0.0.0/8")
    t.add("192.168.0.0/16")
    t.freeze()
    result = t.get_many(["10.1.2.3", "192.168.1.1", "172.16.0.1"])
    assert result == [None, None, None]


def test_get_many_mixed_valueless_and_valued():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "valued"
    t.add("192.168.0.0/16")
    result = t.get_many(["10.1.2.3", "192.168.1.1", "172.16.0.1"])
    assert result == ["valued", None, None]
    t.freeze()
    result = t.get_many(["10.1.2.3", "192.168.1.1", "172.16.0.1"])
    assert result == ["valued", None, None]


# ---------------------------------------------------------------------------
# Pickle round-trip with valueless entries
# ---------------------------------------------------------------------------


def test_pickle_roundtrip_valueless():
    t = pattrie.Pattrie()
    t.add("10.0.0.0/8")
    t.add("192.168.0.0/16")
    t2 = pickle.loads(pickle.dumps(t))
    assert len(t2) == 2
    assert t2.has_key("10.0.0.0/8")
    assert t2.has_key("192.168.0.0/16")
    assert t2["10.1.2.3"] is None
    assert t2["192.168.1.1"] is None


def test_pickle_roundtrip_mixed():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "valued"
    t.add("192.168.0.0/16")
    t2 = pickle.loads(pickle.dumps(t))
    assert t2["10.1.2.3"] == "valued"
    assert t2["192.168.1.1"] is None


def test_pickle_roundtrip_ipv6_valueless():
    t = pattrie.Pattrie(128, socket.AF_INET6)
    t.add("fe80::/32")
    t.add("2001:db8::/32")
    t2 = pickle.loads(pickle.dumps(t))
    assert len(t2) == 2
    assert t2["fe80::1"] is None
    assert t2["2001:db8::1"] is None


# ---------------------------------------------------------------------------
# dump/load round-trip with valueless entries
# ---------------------------------------------------------------------------


def test_dump_load_roundtrip_valueless():
    t = pattrie.Pattrie()
    t.add("10.0.0.0/8")
    t.add("192.168.0.0/16")
    t.freeze()
    with tempfile.NamedTemporaryFile(suffix=".ptri", delete=False) as f:
        path = Path(f.name)
    try:
        t.dump(path)
        t2 = pattrie.Pattrie.load(path)
        assert len(t2) == 2
        assert t2["10.1.2.3"] is None
        assert t2["192.168.1.1"] is None
    finally:
        path.unlink(missing_ok=True)


def test_dump_load_roundtrip_mixed():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "valued"
    t.add("192.168.0.0/16")
    t.freeze()
    with tempfile.NamedTemporaryFile(suffix=".ptri", delete=False) as f:
        path = Path(f.name)
    try:
        t.dump(path)
        t2 = pattrie.Pattrie.load(path)
        assert t2["10.1.2.3"] == "valued"
        assert t2["192.168.1.1"] is None
    finally:
        path.unlink(missing_ok=True)

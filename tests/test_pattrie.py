import socket
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

import pytest

import pattrie


def test_default_constructor():
    t = pattrie.Pattrie()
    assert t is not None


def test_constructor_ipv4():
    t = pattrie.Pattrie(32, socket.AF_INET)
    assert t is not None


def test_constructor_ipv6():
    t = pattrie.Pattrie(128, socket.AF_INET6)
    assert t is not None


def test_constructor_custom_maxbits():
    t = pattrie.Pattrie(24, socket.AF_INET)
    assert t is not None


def test_constructor_invalid_maxbits_type():
    with pytest.raises(TypeError):
        pattrie.Pattrie("bad")  # ty: ignore[invalid-argument-type]


def test_constructor_negative_maxbits():
    with pytest.raises(ValueError):
        pattrie.Pattrie(-1)


def test_constructor_maxbits_exceeds_32_for_ipv4():
    with pytest.raises(ValueError):
        pattrie.Pattrie(33, socket.AF_INET)


def test_constructor_maxbits_exceeds_128_for_ipv6():
    with pytest.raises(ValueError):
        pattrie.Pattrie(129, socket.AF_INET6)


def test_constructor_invalid_family():
    with pytest.raises(ValueError):
        pattrie.Pattrie(32, 99)


def test_len_empty():
    t = pattrie.Pattrie()
    assert len(t) == 0


def test_invalid_key_empty():
    t = pattrie.Pattrie()
    with pytest.raises(ValueError):
        _ = t[""]


def test_invalid_key_garbage():
    t = pattrie.Pattrie()
    with pytest.raises(ValueError):
        _ = t["not-an-ip"]


def test_insert_ipv4():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    assert len(t) == 1


def test_has_key_exact_match():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    assert t.has_key("10.0.0.0/8") is True


def test_has_key_no_match():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    assert t.has_key("11.0.0.0/8") is False


def test_has_key_host_address_is_false():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    assert t.has_key("10.0.0.1") is False


def test_insert_overwrites():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    t["10.0.0.0/8"] = "b"
    assert len(t) == 1
    assert t.has_key("10.0.0.0/8") is True


def test_insert_ipv6():
    t = pattrie.Pattrie(128, socket.AF_INET6)
    t["fe80::/32"] = "hello"
    assert len(t) == 1
    assert t.has_key("fe80::/32") is True


def test_insert_wrong_family():
    t = pattrie.Pattrie(32, socket.AF_INET)
    with pytest.raises(ValueError):
        t["fe80::/32"] = "hello"


def test_getitem_lpm():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    t["10.1.0.0/16"] = "b"
    assert t["10.1.2.3"] == "b"
    assert t["10.2.0.1"] == "a"


def test_getitem_no_match_raises():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    with pytest.raises(KeyError):
        _ = t["192.168.0.1"]


def test_contains_lpm():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    assert "10.1.2.3" in t
    assert "192.168.0.1" not in t


def test_get_lpm():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    assert t.get("10.1.2.3") == "a"
    assert t.get("192.168.0.1") is None
    assert t.get("192.168.0.1", "default") == "default"


def test_get_key_returns_matched_prefix():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    t["10.1.0.0/16"] = "b"
    assert t.get_key("10.1.2.3") == "10.1.0.0/16"
    assert t.get_key("10.2.0.1") == "10.0.0.0/8"
    assert t.get_key("192.168.0.1") is None


def test_getitem_prefix_query():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    assert t["10.1.2.0/24"] == "a"


def test_delete_existing():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    del t["10.0.0.0/8"]
    assert len(t) == 0
    assert t.has_key("10.0.0.0/8") is False


def test_delete_missing_raises():
    t = pattrie.Pattrie()
    with pytest.raises(KeyError):
        del t["10.0.0.0/8"]


def test_delete_method():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    t.delete("10.0.0.0/8")
    assert len(t) == 0


def test_delete_method_missing_raises():
    t = pattrie.Pattrie()
    with pytest.raises(KeyError):
        t.delete("10.0.0.0/8")


def test_delete_frozen_raises():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    t.freeze()
    with pytest.raises(ValueError):
        del t["10.0.0.0/8"]


def test_insert_2arg():
    t = pattrie.Pattrie()
    result = t.insert("10.0.0.0/8", "a")
    assert result is None
    assert t.has_key("10.0.0.0/8") is True


def test_insert_3arg():
    t = pattrie.Pattrie()
    result = t.insert("10.0.0.0", 8, "a")
    assert result is None
    assert t.has_key("10.0.0.0/8") is True


def test_insert_3arg_ipv6():
    t = pattrie.Pattrie(128, socket.AF_INET6)
    t.insert("fe80::", 32, "hello")
    assert t.has_key("fe80::/32") is True


def test_insert_returns_none():
    t = pattrie.Pattrie()
    assert t.insert("10.0.0.0/8", "a") is None


def test_keys_returns_list():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    t["10.1.0.0/16"] = "b"
    assert sorted(t.keys()) == ["10.0.0.0/8", "10.1.0.0/16"]


def test_iter():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    t["10.1.0.0/16"] = "b"
    assert sorted(list(t)) == ["10.0.0.0/8", "10.1.0.0/16"]


def test_iter_empty():
    t = pattrie.Pattrie()
    assert list(t) == []


def test_iter_ipv6():
    t = pattrie.Pattrie(128, socket.AF_INET6)
    t["fe80::/32"] = "a"
    t["2001:db8::/32"] = "b"
    assert len(t.keys()) == 2


def test_freeze_prevents_setitem():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    t.freeze()
    with pytest.raises(ValueError):
        t["10.1.0.0/16"] = "b"


def test_freeze_prevents_insert():
    t = pattrie.Pattrie()
    t.freeze()
    with pytest.raises(ValueError):
        t.insert("10.0.0.0/8", "a")


def test_freeze_prevents_delete():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    t.freeze()
    with pytest.raises(ValueError):
        del t["10.0.0.0/8"]


def test_freeze_allows_reads():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    t.freeze()
    assert t["10.1.2.3"] == "a"
    assert t.get("10.1.2.3") == "a"
    assert t.get_key("10.1.2.3") == "10.0.0.0/8"
    assert t.has_key("10.0.0.0/8") is True
    assert "10.1.2.3" in t


def test_thaw_restores_mutability():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    t.freeze()
    t.thaw()
    t["10.1.0.0/16"] = "b"
    assert len(t) == 2


def test_freeze_concurrent_reads():
    """Frozen trie must serve concurrent reads from multiple threads."""
    import threading

    t = pattrie.Pattrie()
    for i in range(256):
        t[f"{i}.0.0.0/8"] = str(i)
    t.freeze()

    results = {}
    errors = []

    def lookup(tid):
        try:
            results[tid] = t[f"{tid}.1.2.3"]
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=lookup, args=(i,)) for i in range(10)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    assert not errors
    for i in range(10):
        assert results[i] == str(i)


# --- ipaddress module object keys ---


def test_ipv4address_key():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    assert t[IPv4Address("10.1.2.3")] == "a"


def test_ipv4network_key():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    assert t[IPv4Network("10.1.0.0/16")] == "a"


def test_ipv4network_insert():
    t = pattrie.Pattrie()
    t[IPv4Network("10.0.0.0/8")] = "a"
    assert t.has_key("10.0.0.0/8") is True


def test_ipv6address_key():
    t = pattrie.Pattrie(128, socket.AF_INET6)
    t["fe80::/32"] = "hello"
    assert t[IPv6Address("fe80::1")] == "hello"


def test_ipv6network_insert():
    t = pattrie.Pattrie(128, socket.AF_INET6)
    t.insert(IPv6Network("fe80::/32"), "hello")
    assert t.has_key("fe80::/32") is True


# ---------------------------------------------------------------------------
# Compatibility test suite (skip: pickle, raw bytes, children, parent)
# Adapted: IPv6 tests use explicit socket.AF_INET6 (pattrie requires it)
# ---------------------------------------------------------------------------


def test_ported_init():
    with pytest.raises((ValueError, TypeError)):
        pattrie.Pattrie("a")  # ty: ignore[invalid-argument-type]
    with pytest.raises(ValueError):
        pattrie.Pattrie(-1)
    assert isinstance(pattrie.Pattrie(1), pattrie.Pattrie)
    assert isinstance(pattrie.Pattrie(32), pattrie.Pattrie)
    with pytest.raises(ValueError):
        pattrie.Pattrie(33)  # exceeds AF_INET max
    t = pattrie.Pattrie(64, socket.AF_INET6)
    assert isinstance(t, pattrie.Pattrie)
    with pytest.raises(ValueError):
        pattrie.Pattrie(64, socket.AF_INET6 + 1)


def test_ported_basic():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    t["10.1.0.0/16"] = "b"

    assert t["10.0.0.0/8"] == "a"
    assert t["10.1.0.0/16"] == "b"
    assert t["10.0.0.0"] == "a"
    assert t["10.1.0.0"] == "b"
    assert t["10.1.0.1"] == "b"
    assert t["10.0.0.1"] == "a"

    assert "10.0.0.0" in t
    assert "10.1.0.0" in t
    assert "10.0.0.1" in t
    assert "9.0.0.0" not in t
    assert "0.0.0.0" not in t

    assert t.has_key("10.0.0.0/8") is True
    assert t.has_key("10.1.0.0/16") is True
    assert t.has_key("10.2.0.0/16") is False
    assert t.has_key("9.0.0.0/8") is False
    assert t.has_key("10.0.0.0") is False

    assert sorted(["10.0.0.0/8", "10.1.0.0/16"]) == sorted(t.keys())


def test_ported_more_complex():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    t["10.1.0.0/16"] = "b"
    t["10.0.1.0/24"] = "c"
    t["0.0.0.0/0"] = "default route"

    assert t["10.0.0.1/32"] == "a"
    assert t["10.0.0.1"] == "a"
    assert t.has_key("1.0.0.0/8") is False
    for i in range(256):
        assert f"{i}.2.3.4" in t
        if i != 10:
            assert t[f"{i}.2.3.4"] == "default route"


def test_ported_delete():
    t = pattrie.Pattrie(128, socket.AF_INET6)
    t.insert("fe80:abcd::0/96", "xyz")
    t.insert("fe80:beef::0", 96, "abc")
    assert t.get("fe80:abcd::0/96") == "xyz"
    assert t.get("fe80:beef::0/96") == "abc"
    t.delete("fe80:abcd::/96")
    t.delete("fe80:beef::/96")
    with pytest.raises(KeyError):
        t.delete("fe80:abcd::/96")
    with pytest.raises(KeyError):
        t.delete("fe80:beef::/96")
    assert len(t) == 0


def test_ported_insert_remove():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = list(range(10))
    assert t.keys() == ["10.0.0.0/8"]
    t.delete("10.0.0.0/8")
    assert t.keys() == []
    assert t.has_key("10.0.0.0/8") is False

    t["10.0.0.0/8"] = list(range(10))
    t.delete("10.0.0.0/8")
    assert t.keys() == []

    t["10.0.0.0/8"] = list(range(10))
    del t["10.0.0.0/8"]
    assert t.keys() == []

    with pytest.raises(KeyError):
        t2 = pattrie.Pattrie()
        t["10.0.0.0/8"] = list(range(10))
        t2.delete("10.0.0.0/9")


def test_ported_ip6():
    t = pattrie.Pattrie(128, socket.AF_INET6)
    t["fe80::0/32"] = "hello, ip6"
    assert t["fe80::1"] == "hello, ip6"

    addr = IPv6Address("fe80::1")
    xnet = IPv6Network("fe80::1/32", strict=False)
    assert t[addr] == "hello, ip6"
    assert t[xnet] == "hello, ip6"


def test_ported_iteration():
    t = pattrie.Pattrie()
    t["10.1.0.0/16"] = "b"
    t["10.0.0.0/8"] = "a"
    t["10.0.1.0/24"] = "c"
    t["0.0.0.0/0"] = "default route"
    assert sorted(["0.0.0.0/0", "10.0.0.0/8", "10.1.0.0/16", "10.0.1.0/24"]) == sorted(list(t))


def test_ported_iteration2():
    t = pattrie.Pattrie()
    t["10.1.0.0/16"] = "b"
    t["10.0.0.0/8"] = "a"
    t["10.0.1.0/24"] = "c"
    x = iter(t)
    assert next(x) is not None
    assert next(x) is not None
    assert next(x) is not None
    with pytest.raises(StopIteration):
        next(x)


def test_ported_multiple_iter():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = 0
    for _ in range(10):
        assert list(t) == ["10.0.0.0/8"]
        assert t.keys() == ["10.0.0.0/8"]


def test_ported_insert():
    t = pattrie.Pattrie()
    val = t.insert("10.0.0.0/8", "a")
    assert val is None
    assert len(t) == 1
    assert t["10.0.0.0/8"] == "a"
    assert "10.0.0.1" in t


def test_ported_insert2():
    t = pattrie.Pattrie()
    val = t.insert("10.0.0.0", 8, "a")
    assert val is None
    assert len(t) == 1
    assert t["10.0.0.0/8"] == "a"
    assert "10.0.0.1" in t


def test_ported_insert3():
    t = pattrie.Pattrie(128, socket.AF_INET6)
    val = t.insert("fe80::aebc:32ff:fec2:b659/64", "a")
    assert val is None
    assert len(t) == 1
    assert t["fe80::aebc:32ff:fec2:b659/64"] == "a"
    assert "fe80::aebc:32ff:fec2:b659" in t


def test_ported_insert4():
    # raises TypeError (missing required arg) rather than ValueError
    t = pattrie.Pattrie(64, socket.AF_INET6)
    with pytest.raises((ValueError, TypeError)):
        t.insert("fe80::1")  # ty: ignore[no-matching-overload]  # missing prefix length / value


def test_ported_insert_valid_short_v6():
    t = pattrie.Pattrie(128, socket.AF_INET6)
    val = t.insert("::2", "a")
    assert val is None
    assert len(t) == 1
    assert t["::2"] == "a"
    assert "::2" in t


def test_ported_insert_invalid_short_v6():
    t = pattrie.Pattrie(128, socket.AF_INET6)
    with pytest.raises(ValueError, match="Invalid key"):
        t.insert(":2:", "a")


def test_ported_insert_invalid_short_v4():
    t = pattrie.Pattrie()
    with pytest.raises(ValueError, match="Invalid key"):
        t.insert("192.", "a")


def test_ported_get():
    t = pattrie.Pattrie()
    t.insert("10.0.0.0/8", "a")
    assert t.get("10.0.0.0/8", "X") == "a"
    assert t.get("11.0.0.0/8", "X") == "X"


def test_ported_get2():
    t = pattrie.Pattrie(128, socket.AF_INET6)
    t.insert("fe80:abcd::0/96", "xyz")
    t.insert("fe80:beef::0", 96, "abc")
    assert t.get("fe80:abcd::0/96") == "xyz"
    assert t.get("fe80:beef::0/96") == "abc"
    assert sorted(t.keys()) == ["fe80:abcd::/96", "fe80:beef::/96"]


def test_ported_get3():
    t = pattrie.Pattrie(128, socket.AF_INET6)
    t.insert(IPv6Network("2001:218:200e::/56"), "def")
    t.insert(IPv6Network("fe80:abcd::0/96"), "xyz")
    t.insert(IPv6Address("fe80:beef::"), 96, "abc")
    assert sorted(t.keys()) == ["2001:218:200e::/56", "fe80:abcd::/96", "fe80:beef::/96"]
    assert t.get("fe80:abcd::0/96") == "xyz"
    assert t.get("fe80:beef::0/96") == "abc"
    assert t.get(IPv6Network("fe80:abcd::0/96")) == "xyz"
    assert t.get(IPv6Network("fe80:beef::0/96")) == "abc"


def test_ported_get_key():
    t = pattrie.Pattrie()
    t.insert("10.0.0.0/8", "a")
    assert t.get_key("10.0.0.0/8") == "10.0.0.0/8"
    assert t.get_key("10.42.42.42") == "10.0.0.0/8"
    assert t.get_key("11.0.0.0/8") is None
    t.insert("10.42.0.0/16", "b")
    assert t.get_key("10.42.42.42") == "10.42.0.0/16"


def test_ported_get_key_ip6():
    t = pattrie.Pattrie(128, socket.AF_INET6)
    t.insert("2001:db8:10::/48", "a")
    assert t.get_key("2001:db8:10::/48") == "2001:db8:10::/48"
    assert t.get_key("2001:db8:10:42::1") == "2001:db8:10::/48"
    assert t.get_key("2001:db8:11::/48") is None
    t.insert("2001:db8:10:42::/64", "b")
    assert t.get_key("2001:db8:10:42::1") == "2001:db8:10:42::/64"


def test_ported_exceptions():
    t = pattrie.Pattrie(32)
    with pytest.raises(ValueError):
        t.insert("1.2.3/24", "a")
    with pytest.raises(KeyError):
        _ = t["1.2.3.0/24"]
    with pytest.raises(ValueError):
        _ = t["1.2.3/24"]
    with pytest.raises(ValueError):
        t.get("1.2.3/24")
    with pytest.raises(ValueError):
        t.delete("1.2.3/24")
    with pytest.raises(KeyError):
        t.delete("1.2.3.0/24")
    assert t.has_key("1.2.3.0/24") is False
    with pytest.raises(ValueError):
        t.has_key("1.2.3/24")
    assert "1.2.3.0/24" not in t


# ---------------------------------------------------------------------------
# maxbits enforcement
# ---------------------------------------------------------------------------


def test_maxbits_rejects_longer_prefix():
    t = pattrie.Pattrie(24)
    with pytest.raises(ValueError):
        t["10.0.0.0/25"] = "a"


def test_maxbits_accepts_equal_prefix():
    t = pattrie.Pattrie(24)
    t["10.0.0.0/24"] = "a"
    assert t.has_key("10.0.0.0/24") is True


# ---------------------------------------------------------------------------
# Int key fast path (IPv4 address as u32)
# ---------------------------------------------------------------------------


def test_int_key_lookup():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "rfc1918"
    # int(IPv4Address("10.1.2.3")) == 0x0A010203
    assert t[0x0A010203] == "rfc1918"


def test_int_key_contains():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    assert 0x0A000001 in t
    assert 0xC0A80001 not in t  # 192.168.0.1


def test_int_key_get():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    assert t.get(0x0A000001) == "a"
    assert t.get(0xC0A80001) is None


def test_int_key_wrong_family():
    t = pattrie.Pattrie(128, socket.AF_INET6)
    with pytest.raises(ValueError):
        _ = t[0x0A010203]


# ---------------------------------------------------------------------------
# get_many
# ---------------------------------------------------------------------------


def test_get_many_basic():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    t["10.1.0.0/16"] = "b"
    result = t.get_many(["10.1.2.3", "10.2.0.1", "192.168.0.1"])
    assert result == ["b", "a", None]


def test_get_many_empty_input():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    assert t.get_many([]) == []


def test_get_many_default():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    result = t.get_many(["10.1.2.3", "192.168.0.1"], default="miss")
    assert result == ["a", "miss"]


def test_get_many_all_miss():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    result = t.get_many(["192.168.0.1", "172.16.0.1"])
    assert result == [None, None]


def test_get_many_invalid_key_returns_default():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    result = t.get_many(["10.1.2.3", "not-an-ip", "10.2.0.1"])
    assert result == ["a", None, "a"]


def test_get_many_ipaddress_keys():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    result = t.get_many([IPv4Address("10.1.2.3"), IPv4Address("192.168.0.1")])
    assert result == ["a", None]


def test_get_many_frozen():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    t["10.1.0.0/16"] = "b"
    t.freeze()
    result = t.get_many(["10.1.2.3", "10.2.0.1", "192.168.0.1"])
    assert result == ["b", "a", None]


def test_get_many_frozen_default():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    t.freeze()
    result = t.get_many(["10.1.2.3", "192.168.0.1"], default="miss")
    assert result == ["a", "miss"]


def test_get_many_frozen_concurrent():
    """Frozen get_many must serve concurrent calls from multiple threads."""
    import threading

    t = pattrie.Pattrie()
    for i in range(256):
        t[f"{i}.0.0.0/8"] = str(i)
    t.freeze()

    results = {}
    errors = []

    def batch_lookup(tid):
        try:
            ips = [f"{tid}.{j}.0.1" for j in range(10)]
            vals = t.get_many(ips)
            results[tid] = vals
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=batch_lookup, args=(i,)) for i in range(10)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    assert not errors
    for i in range(10):
        assert all(v == str(i) for v in results[i])


def test_get_many_ipv6():
    t = pattrie.Pattrie(128, socket.AF_INET6)
    t["fe80::/10"] = "link-local"
    t["2001:db8::/32"] = "docs"
    result = t.get_many(["fe80::1", "2001:db8::1", "::1"])
    assert result == ["link-local", "docs", None]


def test_get_many_preserves_order():
    t = pattrie.Pattrie()
    for i in range(10):
        t[f"{i}.0.0.0/8"] = i
    ips = [f"{i}.1.2.3" for i in range(9, -1, -1)]
    result = t.get_many(ips)
    assert result == list(range(9, -1, -1))


# ---------------------------------------------------------------------------
# children()
# ---------------------------------------------------------------------------


def test_children_basic():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    t["10.1.0.0/16"] = "b"
    t["10.1.1.0/24"] = "c"
    t["10.2.0.0/16"] = "d"
    result = sorted(t.children("10.0.0.0/8"))
    assert result == ["10.1.0.0/16", "10.1.1.0/24", "10.2.0.0/16"]


def test_children_excludes_self():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    t["10.1.0.0/16"] = "b"
    assert "10.0.0.0/8" not in t.children("10.0.0.0/8")


def test_children_empty_no_descendants():
    t = pattrie.Pattrie()
    t["10.1.1.0/24"] = "c"
    assert t.children("10.1.1.0/24") == []


def test_children_unstored_prefix():
    """Returns descendants even if prefix is not itself stored."""
    t = pattrie.Pattrie()
    t["10.1.0.0/16"] = "b"
    t["10.1.1.0/24"] = "c"
    result = sorted(t.children("10.0.0.0/9"))
    assert result == ["10.1.0.0/16", "10.1.1.0/24"]


def test_children_empty_trie():
    t = pattrie.Pattrie()
    assert t.children("10.0.0.0/8") == []


def test_children_wrong_family_raises():
    t = pattrie.Pattrie()
    with pytest.raises(ValueError):
        t.children("fe80::/32")


def test_children_ipv6():
    t = pattrie.Pattrie(128, socket.AF_INET6)
    t["fe80::/16"] = "a"
    t["fe80::/32"] = "b"
    t["fe80::/48"] = "c"
    result = sorted(t.children("fe80::/16"))
    assert result == ["fe80::/32", "fe80::/48"]


def test_children_no_match_outside_range():
    t = pattrie.Pattrie()
    t["192.168.0.0/16"] = "a"
    assert t.children("10.0.0.0/8") == []


# ---------------------------------------------------------------------------
# parent()
# ---------------------------------------------------------------------------


def test_parent_basic():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    t["10.1.0.0/16"] = "b"
    t["10.1.1.0/24"] = "c"
    assert t.parent("10.1.1.0/24") == "10.1.0.0/16"
    assert t.parent("10.1.0.0/16") == "10.0.0.0/8"
    assert t.parent("10.0.0.0/8") is None


def test_parent_returns_closest_not_distant_ancestor():
    """parent() returns the most specific (closest) covering prefix."""
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    t["10.1.0.0/16"] = "b"
    assert t.parent("10.1.1.0/24") == "10.1.0.0/16"


def test_parent_unstored_prefix():
    """Find covering prefix even if input is not stored."""
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    assert t.parent("10.2.0.0/16") == "10.0.0.0/8"


def test_parent_no_covering_prefix_returns_none():
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    t["192.168.0.0/16"] = "b"
    assert t.parent("192.168.0.0/16") is None


def test_parent_empty_trie():
    t = pattrie.Pattrie()
    assert t.parent("10.0.0.0/8") is None


def test_parent_wrong_family_raises():
    t = pattrie.Pattrie()
    with pytest.raises(ValueError):
        t.parent("fe80::/32")


def test_parent_top_level_prefix_returns_none():
    """Stored prefix with no parent returns None (not KeyError)."""
    t = pattrie.Pattrie()
    t["10.0.0.0/8"] = "a"
    assert t.parent("10.0.0.0/8") is None


def test_parent_ipv6():
    t = pattrie.Pattrie(128, socket.AF_INET6)
    t["fe80::/16"] = "a"
    t["fe80::/32"] = "b"
    t["fe80::/48"] = "c"
    assert t.parent("fe80::/48") == "fe80::/32"
    assert t.parent("fe80::/32") == "fe80::/16"
    assert t.parent("fe80::/16") is None

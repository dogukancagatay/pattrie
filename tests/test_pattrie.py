import socket
import pytest
import pattrie


def test_default_constructor():
    t = pattrie.PyTricia()
    assert t is not None


def test_constructor_ipv4():
    t = pattrie.PyTricia(32, socket.AF_INET)
    assert t is not None


def test_constructor_ipv6():
    t = pattrie.PyTricia(128, socket.AF_INET6)
    assert t is not None


def test_constructor_custom_maxbits():
    t = pattrie.PyTricia(24, socket.AF_INET)
    assert t is not None


def test_constructor_invalid_maxbits_type():
    with pytest.raises(TypeError):
        pattrie.PyTricia("bad")


def test_constructor_negative_maxbits():
    with pytest.raises(ValueError):
        pattrie.PyTricia(-1)


def test_constructor_maxbits_exceeds_32_for_ipv4():
    with pytest.raises(ValueError):
        pattrie.PyTricia(33, socket.AF_INET)


def test_constructor_maxbits_exceeds_128_for_ipv6():
    with pytest.raises(ValueError):
        pattrie.PyTricia(129, socket.AF_INET6)


def test_constructor_invalid_family():
    with pytest.raises(ValueError):
        pattrie.PyTricia(32, 99)


def test_len_empty():
    t = pattrie.PyTricia()
    assert len(t) == 0


def test_invalid_key_empty():
    t = pattrie.PyTricia()
    with pytest.raises(ValueError):
        _ = t[""]


def test_invalid_key_garbage():
    t = pattrie.PyTricia()
    with pytest.raises(ValueError):
        _ = t["not-an-ip"]


def test_insert_ipv4():
    t = pattrie.PyTricia()
    t["10.0.0.0/8"] = "a"
    assert len(t) == 1


def test_has_key_exact_match():
    t = pattrie.PyTricia()
    t["10.0.0.0/8"] = "a"
    assert t.has_key("10.0.0.0/8") is True


def test_has_key_no_match():
    t = pattrie.PyTricia()
    t["10.0.0.0/8"] = "a"
    assert t.has_key("11.0.0.0/8") is False


def test_has_key_host_address_is_false():
    t = pattrie.PyTricia()
    t["10.0.0.0/8"] = "a"
    assert t.has_key("10.0.0.1") is False


def test_insert_overwrites():
    t = pattrie.PyTricia()
    t["10.0.0.0/8"] = "a"
    t["10.0.0.0/8"] = "b"
    assert len(t) == 1
    assert t.has_key("10.0.0.0/8") is True


def test_insert_ipv6():
    t = pattrie.PyTricia(128, socket.AF_INET6)
    t["fe80::/32"] = "hello"
    assert len(t) == 1
    assert t.has_key("fe80::/32") is True


def test_insert_wrong_family():
    t = pattrie.PyTricia(32, socket.AF_INET)
    with pytest.raises(ValueError):
        t["fe80::/32"] = "hello"


def test_getitem_lpm():
    t = pattrie.PyTricia()
    t["10.0.0.0/8"] = "a"
    t["10.1.0.0/16"] = "b"
    assert t["10.1.2.3"] == "b"
    assert t["10.2.0.1"] == "a"


def test_getitem_no_match_raises():
    t = pattrie.PyTricia()
    t["10.0.0.0/8"] = "a"
    with pytest.raises(KeyError):
        _ = t["192.168.0.1"]


def test_contains_lpm():
    t = pattrie.PyTricia()
    t["10.0.0.0/8"] = "a"
    assert "10.1.2.3" in t
    assert "192.168.0.1" not in t


def test_get_lpm():
    t = pattrie.PyTricia()
    t["10.0.0.0/8"] = "a"
    assert t.get("10.1.2.3") == "a"
    assert t.get("192.168.0.1") is None
    assert t.get("192.168.0.1", "default") == "default"


def test_get_key_returns_matched_prefix():
    t = pattrie.PyTricia()
    t["10.0.0.0/8"] = "a"
    t["10.1.0.0/16"] = "b"
    assert t.get_key("10.1.2.3") == "10.1.0.0/16"
    assert t.get_key("10.2.0.1") == "10.0.0.0/8"
    assert t.get_key("192.168.0.1") is None


def test_getitem_prefix_query():
    t = pattrie.PyTricia()
    t["10.0.0.0/8"] = "a"
    assert t["10.1.2.0/24"] == "a"


def test_delete_existing():
    t = pattrie.PyTricia()
    t["10.0.0.0/8"] = "a"
    del t["10.0.0.0/8"]
    assert len(t) == 0
    assert t.has_key("10.0.0.0/8") is False


def test_delete_missing_raises():
    t = pattrie.PyTricia()
    with pytest.raises(KeyError):
        del t["10.0.0.0/8"]


def test_delete_method():
    t = pattrie.PyTricia()
    t["10.0.0.0/8"] = "a"
    t.delete("10.0.0.0/8")
    assert len(t) == 0


def test_delete_method_missing_raises():
    t = pattrie.PyTricia()
    with pytest.raises(KeyError):
        t.delete("10.0.0.0/8")


def test_delete_frozen_raises():
    t = pattrie.PyTricia()
    t["10.0.0.0/8"] = "a"
    t.freeze()
    with pytest.raises(ValueError):
        del t["10.0.0.0/8"]


def test_insert_2arg():
    t = pattrie.PyTricia()
    result = t.insert("10.0.0.0/8", "a")
    assert result is None
    assert t.has_key("10.0.0.0/8") is True


def test_insert_3arg():
    t = pattrie.PyTricia()
    result = t.insert("10.0.0.0", 8, "a")
    assert result is None
    assert t.has_key("10.0.0.0/8") is True


def test_insert_3arg_ipv6():
    t = pattrie.PyTricia(128, socket.AF_INET6)
    t.insert("fe80::", 32, "hello")
    assert t.has_key("fe80::/32") is True


def test_insert_returns_none():
    t = pattrie.PyTricia()
    assert t.insert("10.0.0.0/8", "a") is None


def test_keys_returns_list():
    t = pattrie.PyTricia()
    t["10.0.0.0/8"] = "a"
    t["10.1.0.0/16"] = "b"
    assert sorted(t.keys()) == ["10.0.0.0/8", "10.1.0.0/16"]


def test_iter():
    t = pattrie.PyTricia()
    t["10.0.0.0/8"] = "a"
    t["10.1.0.0/16"] = "b"
    assert sorted(list(t)) == ["10.0.0.0/8", "10.1.0.0/16"]


def test_iter_empty():
    t = pattrie.PyTricia()
    assert list(t) == []


def test_iter_ipv6():
    t = pattrie.PyTricia(128, socket.AF_INET6)
    t["fe80::/32"] = "a"
    t["2001:db8::/32"] = "b"
    assert len(t.keys()) == 2


def test_freeze_prevents_setitem():
    t = pattrie.PyTricia()
    t["10.0.0.0/8"] = "a"
    t.freeze()
    with pytest.raises(ValueError):
        t["10.1.0.0/16"] = "b"


def test_freeze_prevents_insert():
    t = pattrie.PyTricia()
    t.freeze()
    with pytest.raises(ValueError):
        t.insert("10.0.0.0/8", "a")


def test_freeze_prevents_delete():
    t = pattrie.PyTricia()
    t["10.0.0.0/8"] = "a"
    t.freeze()
    with pytest.raises(ValueError):
        del t["10.0.0.0/8"]


def test_freeze_allows_reads():
    t = pattrie.PyTricia()
    t["10.0.0.0/8"] = "a"
    t.freeze()
    assert t["10.1.2.3"] == "a"
    assert t.get("10.1.2.3") == "a"
    assert t.get_key("10.1.2.3") == "10.0.0.0/8"
    assert t.has_key("10.0.0.0/8") is True
    assert "10.1.2.3" in t


def test_thaw_restores_mutability():
    t = pattrie.PyTricia()
    t["10.0.0.0/8"] = "a"
    t.freeze()
    t.thaw()
    t["10.1.0.0/16"] = "b"
    assert len(t) == 2


def test_freeze_concurrent_reads():
    """Frozen trie must serve concurrent reads from multiple threads."""
    import threading
    t = pattrie.PyTricia()
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

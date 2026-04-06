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

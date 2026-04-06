import copy
import pickle
import socket

import pytest

from pattrie import Pattrie


def test_roundtrip_basic():
    t = Pattrie()
    t["10.0.0.0/8"] = "rfc1918"
    t["192.168.0.0/16"] = "home"
    t2 = pickle.loads(pickle.dumps(t))
    assert t2["10.1.2.3"] == "rfc1918"
    assert t2["192.168.1.1"] == "home"
    assert len(t2) == 2


def test_roundtrip_preserves_maxbits():
    t = Pattrie(maxbits=24)
    t["10.0.0.0/8"] = 1
    t2 = pickle.loads(pickle.dumps(t))
    t2.thaw()
    with pytest.raises(ValueError):
        t2["10.0.0.0/25"] = 2


def test_roundtrip_preserves_frozen():
    t = Pattrie()
    t["10.0.0.0/8"] = "val"
    t.freeze()
    t2 = pickle.loads(pickle.dumps(t))
    assert t2["10.1.2.3"] == "val"
    with pytest.raises(ValueError):
        t2["1.0.0.0/8"] = "new"


def test_roundtrip_unfrozen_allows_mutation():
    t = Pattrie()
    t["10.0.0.0/8"] = "val"
    t2 = pickle.loads(pickle.dumps(t))
    t2["1.0.0.0/8"] = "new"
    assert len(t2) == 2


def test_roundtrip_empty():
    t = Pattrie()
    t2 = pickle.loads(pickle.dumps(t))
    assert len(t2) == 0


def test_roundtrip_non_string_values():
    t = Pattrie()
    t["10.0.0.0/8"] = {"asn": 64512, "tags": ["private"]}
    t2 = pickle.loads(pickle.dumps(t))
    assert t2["10.0.0.1"] == {"asn": 64512, "tags": ["private"]}


def test_roundtrip_ipv6():
    t = Pattrie(maxbits=128, family=socket.AF_INET6)
    t["2001:db8::/32"] = "documentation"
    t["::1/128"] = "loopback"
    t2 = pickle.loads(pickle.dumps(t))
    assert t2["2001:db8::1"] == "documentation"
    assert t2["::1"] == "loopback"


def test_deepcopy_is_independent():
    t = Pattrie()
    t["10.0.0.0/8"] = [1, 2, 3]
    t2 = copy.deepcopy(t)
    t2["10.0.0.0/8"] = "replaced"
    assert t["10.1.1.1"] == [1, 2, 3]
    assert t2["10.1.1.1"] == "replaced"

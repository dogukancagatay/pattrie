"""Static type-checking smoke test — checked by ty in CI, not run by pytest."""

import socket

import pattrie

t = pattrie.Pattrie(32, socket.AF_INET)
t["10.0.0.0/8"] = "hello"
val: object = t["10.1.2.3"]
key: str | None = t.get_key("10.1.2.3")
found: bool = "10.1.2.3" in t
many: list[object] = t.get_many(["10.1.2.3", "192.168.0.1"])

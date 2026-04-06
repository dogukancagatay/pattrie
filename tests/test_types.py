import pattrie
import socket

t = pattrie.Pattrie(32, socket.AF_INET)
t["10.0.0.0/8"] = "hello"
val: object = t["10.1.2.3"]
key: str | None = t.get_key("10.1.2.3")
found: bool = "10.1.2.3" in t

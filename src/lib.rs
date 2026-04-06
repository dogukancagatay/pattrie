use pyo3::prelude::*;
use pyo3::exceptions::{PyKeyError, PyValueError};
use pyo3::intern;
use pyo3::types::{PyDict, PyList, PyString, PyTuple};
use prefix_trie::PrefixMap;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::sync::{Arc, RwLock};

enum TrieInner {
    V4(PrefixMap<Ipv4Net, Py<PyAny>>),
    V6(PrefixMap<Ipv6Net, Py<PyAny>>),
}

/// Core string parsing logic — shared by parse_key and the GIL-free path in get_many.
fn parse_key_from_str(s: &str, family: i32, af_inet: i32) -> PyResult<IpNet> {
    if s.is_empty() {
        return Err(PyValueError::new_err("Invalid key: empty string"));
    }

    let net: IpNet = if s.contains('/') {
        s.parse().map_err(|_| PyValueError::new_err(format!("Invalid key: {}", s)))?
    } else {
        let addr: std::net::IpAddr = s
            .parse()
            .map_err(|_| PyValueError::new_err(format!("Invalid key: {}", s)))?;
        match addr {
            std::net::IpAddr::V4(a) => IpNet::V4(Ipv4Net::new(a, 32).unwrap()),
            std::net::IpAddr::V6(a) => IpNet::V6(Ipv6Net::new(a, 128).unwrap()),
        }
    };

    let is_v4 = matches!(net, IpNet::V4(_));
    if (family == af_inet) != is_v4 {
        return Err(PyValueError::new_err(format!(
            "Address family mismatch: trie is {}, got {}",
            if family == af_inet { "IPv4" } else { "IPv6" },
            s
        )));
    }

    Ok(net)
}

/// Parse a Python key (str or ipaddress object) into an IpNet.
/// For bare addresses (no /len), uses /32 for IPv4 and /128 for IPv6.
/// Validates against the trie's address family.
///
/// Fast paths (in order):
///   1. Python str   — zero-copy, no allocation.
///   2. ipaddress objects — extract packed bytes + optional prefixlen directly.
///   3. bare int     — IPv4 address as u32 (network/big-endian byte order).
fn parse_key(py: Python<'_>, key: &Bound<'_, PyAny>, family: i32, af_inet: i32) -> PyResult<IpNet> {
    // Fast path 1: Python str — borrow &str directly, no allocation.
    if let Ok(py_str) = key.cast::<PyString>() {
        return parse_key_from_str(py_str.to_str()?, family, af_inet);
    }

    // Fast path 2: ipaddress.IPv4Address / IPv6Address / IPv4Network / IPv6Network.
    // All expose .packed (bytes) and networks also expose .prefixlen (int).
    if let Ok(packed_obj) = key.getattr(intern!(py, "packed")) {
        if let Ok(bytes) = packed_obj.extract::<&[u8]>() {
            let prefix_len: u8 = key.getattr(intern!(py, "prefixlen"))
                .and_then(|v| v.extract::<u8>())
                .unwrap_or(if bytes.len() == 4 { 32 } else { 128 });
            let net = match bytes.len() {
                4 => {
                    let octets: [u8; 4] = bytes.try_into().unwrap();
                    IpNet::V4(Ipv4Net::new(std::net::Ipv4Addr::from(octets), prefix_len)
                        .map_err(|e| PyValueError::new_err(e.to_string()))?)
                }
                16 => {
                    let octets: [u8; 16] = bytes.try_into().unwrap();
                    IpNet::V6(Ipv6Net::new(std::net::Ipv6Addr::from(octets), prefix_len)
                        .map_err(|e| PyValueError::new_err(e.to_string()))?)
                }
                _ => return Err(PyValueError::new_err(format!("Invalid key: {}", key.str()?))),
            };
            let is_v4 = matches!(net, IpNet::V4(_));
            if (family == af_inet) != is_v4 {
                return Err(PyValueError::new_err(format!(
                    "Address family mismatch: trie is {}, got {}",
                    if family == af_inet { "IPv4" } else { "IPv6" },
                    key.str()?
                )));
            }
            return Ok(net);
        }
    }

    // Fast path 3: bare Python int → IPv4 address as u32 (network byte order).
    if let Ok(n) = key.extract::<u32>() {
        if family != af_inet {
            return Err(PyValueError::new_err(
                "Address family mismatch: trie is IPv6, got int (IPv4)",
            ));
        }
        return Ok(IpNet::V4(Ipv4Net::new(std::net::Ipv4Addr::from(n), 32).unwrap()));
    }

    // Fallback: stringify and parse.
    let s = key.str()?;
    parse_key_from_str(s.to_str()?, family, af_inet)
}

/// Parse a key as a network prefix, zeroing host bits: "10.1.2.3/8" → "10.0.0.0/8".
fn parse_network_key(py: Python<'_>, key: &Bound<'_, PyAny>, family: i32, af_inet: i32) -> PyResult<IpNet> {
    Ok(parse_key(py, key, family, af_inet)?.trunc())
}

#[pyclass(name = "Pattrie", module = "pattrie")]
struct Pattrie {
    inner: Arc<RwLock<TrieInner>>,
    maxbits: u8,
    family: i32,
    /// Cached value of socket.AF_INET — resolved once at construction, avoids per-call import.
    af_inet: i32,
    frozen: bool,
}

#[pymethods]
impl Pattrie {
    #[new]
    #[pyo3(signature = (maxbits=32, family=2))]
    fn new(py: Python<'_>, maxbits: i64, family: i64) -> PyResult<Self> {
        let socket = py.import("socket")?;
        let af_inet: i64 = socket.getattr("AF_INET")?.extract()?;
        let af_inet6: i64 = socket.getattr("AF_INET6")?.extract()?;

        if family != af_inet && family != af_inet6 {
            return Err(PyValueError::new_err(format!(
                "Invalid address family: {}. Use socket.AF_INET or socket.AF_INET6.",
                family
            )));
        }

        let max_allowed: i64 = if family == af_inet { 32 } else { 128 };

        if maxbits < 1 || maxbits > max_allowed {
            return Err(PyValueError::new_err(format!(
                "maxbits must be between 1 and {} for this address family, got {}",
                max_allowed, maxbits
            )));
        }

        let inner = if family == af_inet {
            TrieInner::V4(PrefixMap::new())
        } else {
            TrieInner::V6(PrefixMap::new())
        };

        Ok(Pattrie {
            inner: Arc::new(RwLock::new(inner)),
            maxbits: maxbits as u8,
            family: family as i32,
            af_inet: af_inet as i32,
            frozen: false,
        })
    }

    fn __len__(&self) -> usize {
        let guard = self.inner.read().unwrap();
        match &*guard {
            TrieInner::V4(m) => m.len(),
            TrieInner::V6(m) => m.len(),
        }
    }

    fn __setitem__(&mut self, py: Python<'_>, key: &Bound<'_, PyAny>, value: Py<PyAny>) -> PyResult<()> {
        if self.frozen {
            return Err(PyValueError::new_err("Pattrie is frozen and cannot be modified"));
        }
        let af_inet = self.af_inet;
        let net = parse_network_key(py, key, self.family, af_inet)?;

        let prefix_len = net.prefix_len();
        if prefix_len > self.maxbits {
            return Err(PyValueError::new_err(format!(
                "Prefix length {} exceeds maxbits {}",
                prefix_len, self.maxbits
            )));
        }

        let mut guard = self.inner.write().unwrap();
        match (&mut *guard, net) {
            (TrieInner::V4(map), IpNet::V4(v4)) => { map.insert(v4, value.clone_ref(py)); }
            (TrieInner::V6(map), IpNet::V6(v6)) => { map.insert(v6, value.clone_ref(py)); }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn has_key(&self, _py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<bool> {
        let af_inet = self.af_inet;
        let net = parse_network_key(_py, key, self.family, af_inet)?;

        let guard = self.inner.read().unwrap();
        let found = match (&*guard, net) {
            (TrieInner::V4(map), IpNet::V4(v4)) => map.contains_key(&v4),
            (TrieInner::V6(map), IpNet::V6(v6)) => map.contains_key(&v6),
            _ => false,
        };
        Ok(found)
    }

    fn __getitem__(&self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let af_inet = self.af_inet;
        let net = parse_key(py, key, self.family, af_inet)?;

        if self.frozen {
            let inner_arc = Arc::clone(&self.inner);
            let matched: Option<IpNet> = py.detach(|| {
                let guard = inner_arc.read().unwrap();
                match (&*guard, &net) {
                    (TrieInner::V4(map), IpNet::V4(v4)) => {
                        map.get_lpm(v4).map(|(prefix, _)| IpNet::V4(*prefix))
                    }
                    (TrieInner::V6(map), IpNet::V6(v6)) => {
                        map.get_lpm(v6).map(|(prefix, _)| IpNet::V6(*prefix))
                    }
                    _ => None,
                }
            });
            match matched {
                None => Err(PyKeyError::new_err(format!("No match for key: {}", net))),
                Some(matched_prefix) => {
                    let guard = self.inner.read().unwrap();
                    let result = match (&*guard, &matched_prefix) {
                        (TrieInner::V4(map), IpNet::V4(v4)) => map.get(v4).map(|v| v.clone_ref(py)),
                        (TrieInner::V6(map), IpNet::V6(v6)) => map.get(v6).map(|v| v.clone_ref(py)),
                        _ => None,
                    };
                    result.ok_or_else(|| PyKeyError::new_err(format!("No match for key: {}", net)))
                }
            }
        } else {
            let guard = self.inner.read().unwrap();
            let result = match (&*guard, &net) {
                (TrieInner::V4(map), IpNet::V4(v4)) => map.get_lpm(v4).map(|(_, v)| v.clone_ref(py)),
                (TrieInner::V6(map), IpNet::V6(v6)) => map.get_lpm(v6).map(|(_, v)| v.clone_ref(py)),
                _ => None,
            };
            result.ok_or_else(|| PyKeyError::new_err(format!("No match for key: {}", net)))
        }
    }

    fn __contains__(&self, _py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<bool> {
        let af_inet = self.af_inet;
        let net = match parse_key(_py, key, self.family, af_inet) {
            Ok(n) => n,
            Err(_) => return Ok(false),
        };

        let guard = self.inner.read().unwrap();
        Ok(match (&*guard, &net) {
            (TrieInner::V4(map), IpNet::V4(v4)) => map.get_lpm(v4).is_some(),
            (TrieInner::V6(map), IpNet::V6(v6)) => map.get_lpm(v6).is_some(),
            _ => false,
        })
    }

    #[pyo3(signature = (key, default=None))]
    fn get(&self, py: Python<'_>, key: &Bound<'_, PyAny>, default: Option<Py<PyAny>>) -> PyResult<Py<PyAny>> {
        let af_inet = self.af_inet;
        let net = parse_key(py, key, self.family, af_inet)?;

        let guard = self.inner.read().unwrap();
        let result = match (&*guard, &net) {
            (TrieInner::V4(map), IpNet::V4(v4)) => map.get_lpm(v4).map(|(_, v)| v.clone_ref(py)),
            (TrieInner::V6(map), IpNet::V6(v6)) => map.get_lpm(v6).map(|(_, v)| v.clone_ref(py)),
            _ => None,
        };
        Ok(result.unwrap_or_else(|| default.unwrap_or_else(|| py.None())))
    }

    fn get_key(&self, _py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<Option<String>> {
        let af_inet = self.af_inet;
        let net = parse_key(_py, key, self.family, af_inet)?;

        let guard = self.inner.read().unwrap();
        Ok(match (&*guard, &net) {
            (TrieInner::V4(map), IpNet::V4(v4)) => {
                map.get_lpm(v4).map(|(prefix, _)| prefix.to_string())
            }
            (TrieInner::V6(map), IpNet::V6(v6)) => {
                map.get_lpm(v6).map(|(prefix, _)| prefix.to_string())
            }
            _ => None,
        })
    }

    fn __delitem__(&mut self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<()> {
        self.delete(py, key)
    }

    fn delete(&mut self, _py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<()> {
        if self.frozen {
            return Err(PyValueError::new_err("Pattrie is frozen and cannot be modified"));
        }
        let af_inet = self.af_inet;
        let net = parse_network_key(_py, key, self.family, af_inet)?;

        let mut guard = self.inner.write().unwrap();
        let removed = match (&mut *guard, net) {
            (TrieInner::V4(map), IpNet::V4(v4)) => map.remove(&v4).is_some(),
            (TrieInner::V6(map), IpNet::V6(v6)) => map.remove(&v6).is_some(),
            _ => false,
        };

        if removed {
            Ok(())
        } else {
            Err(PyKeyError::new_err(format!("Prefix not found: {}", key.str()?)))
        }
    }

    #[pyo3(signature = (key_or_addr, value_or_prefixlen, value=None))]
    fn insert(
        &mut self,
        py: Python<'_>,
        key_or_addr: &Bound<'_, PyAny>,
        value_or_prefixlen: &Bound<'_, PyAny>,
        value: Option<Py<PyAny>>,
    ) -> PyResult<()> {
        if self.frozen {
            return Err(PyValueError::new_err("Pattrie is frozen and cannot be modified"));
        }
        let af_inet = self.af_inet;

        let (net, val): (IpNet, Py<PyAny>) = if let Some(v) = value {
            // 3-arg form: insert(addr, prefixlen, value)
            let plen: u8 = value_or_prefixlen.extract()?;
            let addr_str = key_or_addr.str()?.to_string();
            let addr: std::net::IpAddr = addr_str
                .parse()
                .map_err(|_| PyValueError::new_err(format!("Invalid address: {}", addr_str)))?;
            let net = match addr {
                std::net::IpAddr::V4(a) => {
                    IpNet::V4(Ipv4Net::new(a, plen).map_err(|e| PyValueError::new_err(e.to_string()))?.trunc())
                }
                std::net::IpAddr::V6(a) => {
                    IpNet::V6(Ipv6Net::new(a, plen).map_err(|e| PyValueError::new_err(e.to_string()))?.trunc())
                }
            };
            let is_v4 = matches!(net, IpNet::V4(_));
            if (self.family == af_inet) != is_v4 {
                return Err(PyValueError::new_err("Address family mismatch"));
            }
            (net, v)
        } else {
            // 2-arg form: insert(prefix, value)
            let net = parse_network_key(py, key_or_addr, self.family, af_inet)?;
            (net, value_or_prefixlen.clone().unbind())
        };

        let prefix_len = net.prefix_len();
        if prefix_len > self.maxbits {
            return Err(PyValueError::new_err(format!(
                "Prefix length {} exceeds maxbits {}",
                prefix_len, self.maxbits
            )));
        }

        let mut guard = self.inner.write().unwrap();
        match (&mut *guard, net) {
            (TrieInner::V4(map), IpNet::V4(v4)) => { map.insert(v4, val); }
            (TrieInner::V6(map), IpNet::V6(v6)) => { map.insert(v6, val); }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn __iter__(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let keys = self.keys();
        let list = pyo3::types::PyList::new(py, &keys)?;
        Ok(list.call_method0("__iter__")?.unbind())
    }

    fn keys(&self) -> Vec<String> {
        let guard = self.inner.read().unwrap();
        match &*guard {
            TrieInner::V4(map) => map.iter().map(|(p, _)| p.to_string()).collect(),
            TrieInner::V6(map) => map.iter().map(|(p, _)| p.to_string()).collect(),
        }
    }

    /// Look up multiple keys in one call, returning a list of values (or `default` on miss).
    ///
    /// When the trie is frozen, the entire batch of trie traversals runs without the GIL,
    /// enabling true parallel use from multiple threads.
    #[pyo3(signature = (keys, default=None))]
    fn get_many(
        &self,
        py: Python<'_>,
        keys: &Bound<'_, pyo3::types::PyList>,
        default: Option<Py<PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let default_val = default.unwrap_or_else(|| py.None());
        let n = keys.len();
        let mut results: Vec<Py<PyAny>> = Vec::with_capacity(n);

        if self.frozen {
            // Phase 1: extract all keys as strings while holding the GIL.
            let mut str_keys: Vec<Option<String>> = Vec::with_capacity(n);
            for item in keys.iter() {
                let s = if let Ok(py_str) = item.cast::<PyString>() {
                    py_str.to_str().map(|s| s.to_owned()).ok()
                } else {
                    item.str().and_then(|ps| ps.to_str().map(|s| s.to_owned())).ok()
                };
                str_keys.push(s);
            }

            let inner_arc = Arc::clone(&self.inner);
            let family = self.family;
            let af_inet = self.af_inet;

            // Phase 2: all trie traversals without the GIL.
            let matched: Vec<Option<IpNet>> = py.detach(|| {
                let guard = inner_arc.read().unwrap();
                str_keys.iter().map(|maybe_s| {
                    let net = parse_key_from_str(maybe_s.as_deref()?, family, af_inet).ok()?;
                    match (&*guard, &net) {
                        (TrieInner::V4(map), IpNet::V4(v4)) => {
                            map.get_lpm(v4).map(|(p, _)| IpNet::V4(*p))
                        }
                        (TrieInner::V6(map), IpNet::V6(v6)) => {
                            map.get_lpm(v6).map(|(p, _)| IpNet::V6(*p))
                        }
                        _ => None,
                    }
                }).collect()
            });

            // Phase 3: clone Python values (needs the GIL).
            let guard = self.inner.read().unwrap();
            for prefix in matched {
                let val = match prefix {
                    None => default_val.clone_ref(py),
                    Some(p) => match (&*guard, &p) {
                        (TrieInner::V4(map), IpNet::V4(v4)) => {
                            map.get(v4).map(|v| v.clone_ref(py))
                                .unwrap_or_else(|| default_val.clone_ref(py))
                        }
                        (TrieInner::V6(map), IpNet::V6(v6)) => {
                            map.get(v6).map(|v| v.clone_ref(py))
                                .unwrap_or_else(|| default_val.clone_ref(py))
                        }
                        _ => default_val.clone_ref(py),
                    },
                };
                results.push(val);
            }
        } else {
            let guard = self.inner.read().unwrap();
            for item in keys.iter() {
                let net = match parse_key(py, &item, self.family, self.af_inet) {
                    Ok(n) => n,
                    Err(_) => {
                        results.push(default_val.clone_ref(py));
                        continue;
                    }
                };
                let val = match (&*guard, &net) {
                    (TrieInner::V4(map), IpNet::V4(v4)) => {
                        map.get_lpm(v4).map(|(_, v)| v.clone_ref(py))
                    }
                    (TrieInner::V6(map), IpNet::V6(v6)) => {
                        map.get_lpm(v6).map(|(_, v)| v.clone_ref(py))
                    }
                    _ => None,
                }.unwrap_or_else(|| default_val.clone_ref(py));
                results.push(val);
            }
        }

        let list = pyo3::types::PyList::new(py, &results)?;
        Ok(list.into_any().unbind())
    }

    fn __reduce__(slf: &Bound<'_, Self>, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let cls = slf.get_type().into_any().unbind();
        let me = slf.borrow();
        let args = PyTuple::new(py, [me.maxbits as i64, me.family as i64])?;
        let state = me.__getstate__(py)?;
        drop(me);
        Ok(PyTuple::new(py, [cls, args.into_any().unbind(), state])?
            .into_any()
            .unbind())
    }

    fn __getstate__(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let guard = self.inner.read().unwrap();
        let build_entry = |prefix: &str, val: &Py<PyAny>| -> PyResult<Py<PyAny>> {
            let pair = PyList::new(py, [
                PyString::new(py, prefix).into_any().unbind(),
                val.clone_ref(py),
            ])?;
            Ok(pair.into_any().unbind())
        };
        let entries: PyResult<Vec<Py<PyAny>>> = match &*guard {
            TrieInner::V4(map) => map.iter().map(|(p, v)| build_entry(&p.to_string(), v)).collect(),
            TrieInner::V6(map) => map.iter().map(|(p, v)| build_entry(&p.to_string(), v)).collect(),
        };
        let dict = PyDict::new(py);
        dict.set_item("frozen", self.frozen)?;
        dict.set_item("entries", PyList::new(py, entries?)?)?;
        Ok(dict.into_any().unbind())
    }

    fn __setstate__(&mut self, py: Python<'_>, state: &Bound<'_, PyAny>) -> PyResult<()> {
        let dict = state.cast::<PyDict>()?;
        let frozen: bool = dict
            .get_item("frozen")?
            .ok_or_else(|| PyValueError::new_err("Missing 'frozen' in pickle state"))?
            .extract()?;
        let entries_obj = dict
            .get_item("entries")?
            .ok_or_else(|| PyValueError::new_err("Missing 'entries' in pickle state"))?;
        let entries_list = entries_obj.cast::<PyList>()?;
        {
            let mut guard = self.inner.write().unwrap();
            for item in entries_list.iter() {
                let pair = item.cast::<PyList>()?;
                let prefix_str: String = pair.get_item(0)?.extract()?;
                let value: Py<PyAny> = pair.get_item(1)?.unbind();
                let net: IpNet = prefix_str.parse().map_err(|_| {
                    PyValueError::new_err(format!("Invalid prefix in pickle state: {prefix_str}"))
                })?;
                match (&mut *guard, net) {
                    (TrieInner::V4(map), IpNet::V4(v4)) => { map.insert(v4, value); }
                    (TrieInner::V6(map), IpNet::V6(v6)) => { map.insert(v6, value); }
                    _ => return Err(PyValueError::new_err("Address family mismatch in pickle state")),
                }
            }
        }
        self.frozen = frozen;
        // Re-cache af_inet in case __new__ was bypassed by pickle
        let socket = py.import("socket")?;
        self.af_inet = socket.getattr("AF_INET")?.extract()?;
        Ok(())
    }

    fn freeze(&mut self) -> PyResult<()> {
        self.frozen = true;
        Ok(())
    }

    fn thaw(&mut self) -> PyResult<()> {
        self.frozen = false;
        Ok(())
    }
}

#[pymodule]
fn _pattrie(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Pattrie>()?;
    Ok(())
}

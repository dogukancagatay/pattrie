use pyo3::prelude::*;
use pyo3::exceptions::{PyKeyError, PyValueError};
use prefix_trie::PrefixMap;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::sync::{Arc, RwLock};

enum TrieInner {
    V4(PrefixMap<Ipv4Net, Py<PyAny>>),
    V6(PrefixMap<Ipv6Net, Py<PyAny>>),
}

/// Parse a Python key (str or ipaddress object) into an IpNet.
/// For bare addresses (no /len), uses /32 for IPv4 and /128 for IPv6.
/// Validates against the trie's address family.
fn parse_key(key: &Bound<'_, PyAny>, family: i32, af_inet: i32) -> PyResult<IpNet> {
    let s = key.str()?.to_string();

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

/// Parse a key as a network prefix, zeroing host bits: "10.1.2.3/8" → "10.0.0.0/8".
fn parse_network_key(key: &Bound<'_, PyAny>, family: i32, af_inet: i32) -> PyResult<IpNet> {
    Ok(parse_key(key, family, af_inet)?.trunc())
}

/// Resolve AF_INET from Python's socket module (platform-safe: Linux=2, macOS=2, but AF_INET6 differs).
fn get_af_inet(py: Python<'_>) -> PyResult<i32> {
    let socket = py.import_bound("socket")?;
    Ok(socket.getattr("AF_INET")?.extract()?)
}

#[pyclass(name = "PyTricia")]
struct PyTricia {
    inner: Arc<RwLock<TrieInner>>,
    maxbits: u8,
    family: i32,
    frozen: bool,
}

#[pymethods]
impl PyTricia {
    #[new]
    #[pyo3(signature = (maxbits=32, family=2))]
    fn new(py: Python<'_>, maxbits: i64, family: i64) -> PyResult<Self> {
        let socket = py.import_bound("socket")?;
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

        Ok(PyTricia {
            inner: Arc::new(RwLock::new(inner)),
            maxbits: maxbits as u8,
            family: family as i32,
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

    fn __setitem__(&mut self, py: Python<'_>, key: &Bound<'_, PyAny>, value: PyObject) -> PyResult<()> {
        if self.frozen {
            return Err(PyValueError::new_err("PyTricia is frozen and cannot be modified"));
        }
        let af_inet = get_af_inet(py)?;
        let net = parse_network_key(key, self.family, af_inet)?;

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

    fn has_key(&self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<bool> {
        let af_inet = get_af_inet(py)?;
        let net = parse_network_key(key, self.family, af_inet)?;

        let guard = self.inner.read().unwrap();
        let found = match (&*guard, net) {
            (TrieInner::V4(map), IpNet::V4(v4)) => map.contains_key(&v4),
            (TrieInner::V6(map), IpNet::V6(v6)) => map.contains_key(&v6),
            _ => false,
        };
        Ok(found)
    }

    fn __getitem__(&self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<PyObject> {
        let af_inet = get_af_inet(py)?;
        let net = parse_key(key, self.family, af_inet)?;

        if self.frozen {
            // Release GIL during trie traversal — enables true concurrent reads.
            // Capture the matched prefix (a pure Rust value) then re-acquire GIL to clone
            // the Python value with a quick exact lookup.
            let inner_arc = Arc::clone(&self.inner);
            let matched: Option<IpNet> = py.allow_threads(|| {
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

    fn __contains__(&self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<bool> {
        let af_inet = get_af_inet(py)?;
        let net = match parse_key(key, self.family, af_inet) {
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
    fn get(&self, py: Python<'_>, key: &Bound<'_, PyAny>, default: Option<PyObject>) -> PyResult<PyObject> {
        let af_inet = get_af_inet(py)?;
        let net = parse_key(key, self.family, af_inet)?;

        let guard = self.inner.read().unwrap();
        let result = match (&*guard, &net) {
            (TrieInner::V4(map), IpNet::V4(v4)) => map.get_lpm(v4).map(|(_, v)| v.clone_ref(py)),
            (TrieInner::V6(map), IpNet::V6(v6)) => map.get_lpm(v6).map(|(_, v)| v.clone_ref(py)),
            _ => None,
        };
        Ok(result.unwrap_or_else(|| default.unwrap_or_else(|| py.None())))
    }

    fn get_key(&self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<Option<String>> {
        let af_inet = get_af_inet(py)?;
        let net = parse_key(key, self.family, af_inet)?;

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

    fn delete(&mut self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<()> {
        if self.frozen {
            return Err(PyValueError::new_err("PyTricia is frozen and cannot be modified"));
        }
        let af_inet = get_af_inet(py)?;
        let net = parse_network_key(key, self.family, af_inet)?;

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
        value: Option<PyObject>,
    ) -> PyResult<()> {
        if self.frozen {
            return Err(PyValueError::new_err("PyTricia is frozen and cannot be modified"));
        }
        let af_inet = get_af_inet(py)?;

        let (net, val): (IpNet, PyObject) = if let Some(v) = value {
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
            let net = parse_network_key(key_or_addr, self.family, af_inet)?;
            (net, value_or_prefixlen.into_py(py))
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

    fn __iter__(&self, py: Python<'_>) -> PyResult<PyObject> {
        let keys = self.keys();
        let list = pyo3::types::PyList::new_bound(py, &keys);
        Ok(list.call_method0("__iter__")?.into_py(py))
    }

    fn keys(&self) -> Vec<String> {
        let guard = self.inner.read().unwrap();
        match &*guard {
            TrieInner::V4(map) => map.iter().map(|(p, _)| p.to_string()).collect(),
            TrieInner::V6(map) => map.iter().map(|(p, _)| p.to_string()).collect(),
        }
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
    m.add_class::<PyTricia>()?;
    Ok(())
}

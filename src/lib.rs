use pyo3::prelude::*;
use pyo3::exceptions::{PyKeyError, PyTypeError, PyValueError};
use pyo3::intern;
use pyo3::types::{PyDict, PyList, PySequence, PyString, PyTuple, PyType};
use prefix_trie::{Prefix, PrefixMap};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::sync::{Arc, RwLock};
use std::io::Write;

/// Strip the `/len` suffix from a CIDR string, returning the bare network address.
fn to_bare_addr(s: &str) -> String {
    match s.split_once('/') {
        Some((addr, _)) => addr.to_owned(),
        None => s.to_owned(),
    }
}

/// Format a prefix string, optionally stripping the `/len` suffix.
fn format_key(s: &str, bare: bool) -> String {
    if bare { to_bare_addr(s) } else { s.to_owned() }
}

/// Find the closest covering prefix (immediate parent) for `prefix`.
/// Uses `.last()` on cover_keys — DoubleEndedIterator is unavailable so .rev() cannot be used.
fn find_parent<P, T>(map: &PrefixMap<P, T>, prefix: &P) -> Option<String>
where
    P: Prefix + PartialEq + std::fmt::Display,
{
    map.cover_keys(prefix)
        .filter(|p| *p != prefix)
        .last()
        .map(|p| p.to_string())
}

/// Collect all stored prefixes more specific than `prefix` (self excluded).
fn find_children<P, T>(map: &PrefixMap<P, T>, prefix: &P) -> Vec<String>
where
    P: Prefix + PartialEq + std::fmt::Display,
{
    map.children(prefix)
        .filter(|(p, _)| *p != prefix)
        .map(|(p, _)| p.to_string())
        .collect()
}

/// Collect all stored values in trie traversal order.
fn collect_values<P: Prefix>(map: &PrefixMap<P, Py<PyAny>>, py: Python<'_>) -> Vec<Py<PyAny>> {
    map.iter().map(|(_, v)| v.clone_ref(py)).collect()
}

/// Collect all stored (prefix, value) pairs in trie traversal order.
fn collect_items<P>(map: &PrefixMap<P, Py<PyAny>>, py: Python<'_>) -> Vec<(String, Py<PyAny>)>
where
    P: Prefix + std::fmt::Display,
{
    map.iter().map(|(p, v)| (p.to_string(), v.clone_ref(py))).collect()
}

/// Collect all stored (prefix, value) covering pairs for `prefix`,
/// most-specific first (reversed cover_keys order).
fn collect_covering_items<P>(
    map: &PrefixMap<P, Py<PyAny>>,
    prefix: &P,
    py: Python<'_>,
) -> PyResult<Vec<Py<PyAny>>>
where
    P: Prefix + std::fmt::Display,
{
    // cover_keys yields from least-specific to most-specific; collect then reverse.
    let pairs: Vec<(&P, &Py<PyAny>)> = map
        .cover_keys(prefix)
        .filter_map(|p| map.get(p).map(|v| (p, v)))
        .collect();

    pairs.into_iter().rev().map(|(p, v)| {
        PyTuple::new(py, [
            PyString::new(py, &p.to_string()).into_any().unbind(),
            v.clone_ref(py),
        ]).map(|t| t.into_any().unbind())
    }).collect()
}

/// Structural equality of two same-family maps: same keys, with Python-equal values.
fn maps_equal<P: Prefix>(
    py: Python<'_>,
    m1: &PrefixMap<P, Py<PyAny>>,
    m2: &PrefixMap<P, Py<PyAny>>,
) -> PyResult<bool> {
    if m1.len() != m2.len() {
        return Ok(false);
    }
    for (k, v) in m1.iter() {
        match m2.get(k) {
            None => return Ok(false),
            Some(v2) => {
                if !v.bind(py).eq(v2.bind(py))? {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

enum TrieInner {
    V4(PrefixMap<Ipv4Net, Py<PyAny>>),
    V6(PrefixMap<Ipv6Net, Py<PyAny>>),
}

impl TrieInner {
    fn insert(&mut self, net: IpNet, val: Py<PyAny>) {
        match (self, net) {
            (TrieInner::V4(map), IpNet::V4(v4)) => { map.insert(v4, val); }
            (TrieInner::V6(map), IpNet::V6(v6)) => { map.insert(v6, val); }
            _ => unreachable!(),
        }
    }
}

enum FrozenKey {
    Str(String),
    Raw(Vec<u8>, Option<u8>),
}

fn check_mutable(frozen: bool) -> PyResult<()> {
    if frozen {
        return Err(PyValueError::new_err("Pattrie is frozen and cannot be modified"));
    }
    Ok(())
}

fn validate_prefix_len(prefix_len: u8, maxbits: u8) -> PyResult<()> {
    if prefix_len > maxbits {
        return Err(PyValueError::new_err(format!(
            "Prefix length {} exceeds maxbits {}",
            prefix_len, maxbits
        )));
    }
    Ok(())
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

/// Build an IpNet from raw network-order address bytes (4 → IPv4, 16 → IPv6)
/// and an optional prefix length (defaults 32 / 128). Validates address family.
///
/// `bytes` is big-endian/network order — exactly what Ipv4Addr/Ipv6Addr::from
/// consume, so no byteswap is applied (unlike the bare-int fast path).
fn net_from_octets(bytes: &[u8], prefix_len: Option<u8>, family: i32, af_inet: i32) -> PyResult<IpNet> {
    let is_v4 = match bytes.len() {
        4 => true,
        16 => false,
        n => return Err(PyValueError::new_err(format!(
            "Invalid raw address: expected 4 or 16 bytes, got {}", n
        ))),
    };
    if (family == af_inet) != is_v4 {
        return Err(PyValueError::new_err(format!(
            "Address family mismatch: trie is {}, got {}-byte raw address",
            if family == af_inet { "IPv4" } else { "IPv6" },
            bytes.len()
        )));
    }
    let map_err = |e: ipnet::PrefixLenError| PyValueError::new_err(e.to_string());
    if is_v4 {
        let octets: [u8; 4] = bytes.try_into().unwrap();
        Ok(IpNet::V4(Ipv4Net::new(std::net::Ipv4Addr::from(octets), prefix_len.unwrap_or(32)).map_err(map_err)?))
    } else {
        let octets: [u8; 16] = bytes.try_into().unwrap();
        Ok(IpNet::V6(Ipv6Net::new(std::net::Ipv6Addr::from(octets), prefix_len.unwrap_or(128)).map_err(map_err)?))
    }
}

/// Extract owned raw-address bytes (and optional prefix length) from a key.
/// Recognizes a `(bytes, prefixlen)` 2-tuple or bare bytes/bytearray/memoryview.
/// Returns `None` for anything else (str, int, ipaddress objects, or a tuple whose
/// prefixlen isn't an int) so callers fall through to their other parse paths. Requires the GIL.
fn extract_raw_bytes_like(key: &Bound<'_, PyAny>) -> Option<(Vec<u8>, Option<u8>)> {
    if let Ok(tup) = key.cast::<PyTuple>() {
        if tup.len() == 2 {
            if let Ok(raw) = tup.get_item(0).ok()?.extract::<Vec<u8>>() {
                if let Ok(plen) = tup.get_item(1).ok()?.extract::<u8>() {
                    return Some((raw, Some(plen)));
                }
            }
        }
        return None;
    }
    // Bare bytes/bytearray/memoryview via the buffer protocol (contiguous only;
    // non-contiguous buffers Err and fall through).
    key.extract::<Vec<u8>>().ok().map(|raw| (raw, None))
}

/// Recognize raw-bytes key forms and build the corresponding `IpNet`.
///
/// Two forms are accepted: a `(bytes, prefixlen)` 2-tuple, or bare bytes/
/// bytearray/memoryview (4 bytes → /32, 16 bytes → /128). Returns `None` for
/// anything else (str, int, ipaddress objects, or a tuple whose prefixlen
/// isn't an int) so the caller falls through to its other parse paths.
fn parse_raw_bytes_like(
    key: &Bound<'_, PyAny>,
    family: i32,
    af_inet: i32,
) -> Option<PyResult<IpNet>> {
    let (raw, plen) = extract_raw_bytes_like(key)?;
    Some(net_from_octets(&raw, plen, family, af_inet))
}

/// Parse a Python key (str or ipaddress object) into an IpNet.
/// For bare addresses (no /len), uses /32 for IPv4 and /128 for IPv6.
/// Validates against the trie's address family.
///
/// Fast paths (in order):
///   1. Python str   — zero-copy, no allocation.
///   2. ipaddress objects — extract packed bytes + optional prefixlen directly.
///   2b. raw address bytes — (bytes, prefixlen) tuple or bare bytes/bytearray/
///       memoryview (4 → /32, 16 → /128); skips string formatting/parsing.
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

    // Fast path 2b: raw address bytes — either a (bytes, prefixlen) 2-tuple or
    // bare bytes/bytearray/memoryview (4 bytes → /32, 16 bytes → /128).
    if let Some(net) = parse_raw_bytes_like(key, family, af_inet) {
        return net;
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

/// A longest-prefix-match (LPM) IP prefix trie.
///
/// See the Python stub (`pattrie/_pattrie.pyi`) for full documentation.
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
        check_mutable(self.frozen)?;
        let net = parse_network_key(py, key, self.family, self.af_inet)?;
        validate_prefix_len(net.prefix_len(), self.maxbits)?;

        let mut guard = self.inner.write().unwrap();
        guard.insert(net, value.clone_ref(py));
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

    #[pyo3(signature = (key, bare=false))]
    fn get_key(&self, _py: Python<'_>, key: &Bound<'_, PyAny>, bare: bool) -> PyResult<Option<String>> {
        let af_inet = self.af_inet;
        let net = parse_key(_py, key, self.family, af_inet)?;

        let guard = self.inner.read().unwrap();
        let full = match (&*guard, &net) {
            (TrieInner::V4(map), IpNet::V4(v4)) => map.get_lpm(v4).map(|(p, _)| p.to_string()),
            (TrieInner::V6(map), IpNet::V6(v6)) => map.get_lpm(v6).map(|(p, _)| p.to_string()),
            _ => None,
        };
        Ok(full.map(|s| format_key(&s, bare)))
    }

    fn __delitem__(&mut self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<()> {
        self.delete(py, key)
    }

    fn delete(&mut self, _py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<()> {
        check_mutable(self.frozen)?;
        let net = parse_network_key(_py, key, self.family, self.af_inet)?;

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

    fn clear(&mut self) -> PyResult<()> {
        check_mutable(self.frozen)?;
        let mut guard = self.inner.write().unwrap();
        match &mut *guard {
            TrieInner::V4(map) => map.clear(),
            TrieInner::V6(map) => map.clear(),
        }
        Ok(())
    }

    #[pyo3(signature = (key, *args))]
    fn pop(&mut self, py: Python<'_>, key: &Bound<'_, PyAny>, args: &Bound<'_, PyTuple>) -> PyResult<Py<PyAny>> {
        // Variadic `*args` so an explicitly-passed default (including `None`) is
        // distinguishable from "no default given" — matching dict.pop semantics.
        if args.len() > 1 {
            return Err(PyTypeError::new_err(format!(
                "pop expected at most 2 arguments, got {}",
                args.len() + 1
            )));
        }
        check_mutable(self.frozen)?;

        let net = parse_network_key(py, key, self.family, self.af_inet)?;
        let mut guard = self.inner.write().unwrap();
        let removed = match (&mut *guard, net) {
            (TrieInner::V4(map), IpNet::V4(v4)) => map.remove(&v4),
            (TrieInner::V6(map), IpNet::V6(v6)) => map.remove(&v6),
            _ => None,
        };
        match removed {
            Some(val) => Ok(val),
            None => {
                if args.is_empty() {
                    Err(PyKeyError::new_err(key.str()?.to_string()))
                } else {
                    Ok(args.get_item(0)?.unbind())
                }
            }
        }
    }

    #[pyo3(signature = (key, default=None))]
    fn setdefault(&mut self, py: Python<'_>, key: &Bound<'_, PyAny>, default: Option<Py<PyAny>>) -> PyResult<Py<PyAny>> {
        let net = parse_network_key(py, key, self.family, self.af_inet)?;
        validate_prefix_len(net.prefix_len(), self.maxbits)?;

        // check_mutable is intentionally deferred: a frozen trie can still serve
        // setdefault when the key already exists (no mutation needed).
        let mut guard = self.inner.write().unwrap();
        let existing = match (&*guard, &net) {
            (TrieInner::V4(map), IpNet::V4(v4)) => map.get(v4).map(|v| v.clone_ref(py)),
            (TrieInner::V6(map), IpNet::V6(v6)) => map.get(v6).map(|v| v.clone_ref(py)),
            _ => None,
        };

        if let Some(val) = existing {
            return Ok(val);
        }

        check_mutable(self.frozen)?;
        let default_val = default.unwrap_or_else(|| py.None());
        guard.insert(net, default_val.clone_ref(py));
        Ok(default_val)
    }

    fn update(&mut self, py: Python<'_>, other: &Bound<'_, PyAny>) -> PyResult<()> {
        check_mutable(self.frozen)?;

        let mut entries: Vec<(IpNet, Py<PyAny>)> = Vec::new();

        let iter_obj: Bound<'_, PyAny> = if let Ok(items_method) = other.getattr(intern!(py, "items")) {
            items_method.call0()?
        } else {
            other.clone()
        };

        for pair_result in iter_obj.try_iter()? {
            let pair = pair_result?;
            let seq = pair.cast::<pyo3::types::PySequence>().map_err(|_| {
                PyTypeError::new_err("update() requires (prefix, value) pairs")
            })?;
            if seq.len()? != 2 {
                return Err(PyTypeError::new_err(
                    "update() requires (prefix, value) pairs",
                ));
            }
            let key = seq.get_item(0)?;
            let value: Py<PyAny> = seq.get_item(1)?.unbind();
            let net = parse_network_key(py, &key, self.family, self.af_inet)?;
            validate_prefix_len(net.prefix_len(), self.maxbits)?;
            entries.push((net, value));
        }

        let mut guard = self.inner.write().unwrap();
        for (net, val) in entries {
            guard.insert(net, val);
        }
        Ok(())
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        let family_name = if self.family == self.af_inet { "AF_INET" } else { "AF_INET6" };

        let guard = self.inner.read().unwrap();
        let total = match &*guard {
            TrieInner::V4(map) => map.len(),
            TrieInner::V6(map) => map.len(),
        };

        const LIMIT: usize = 5;
        let mut pairs: Vec<String> = Vec::with_capacity(LIMIT);
        let iter: Box<dyn Iterator<Item = (String, &Py<PyAny>)>> = match &*guard {
            TrieInner::V4(map) => Box::new(map.iter().map(|(p, v)| (p.to_string(), v))),
            TrieInner::V6(map) => Box::new(map.iter().map(|(p, v)| (p.to_string(), v))),
        };
        for (p, v) in iter.take(LIMIT) {
            let val_repr = v.bind(py).repr()?.to_string();
            pairs.push(format!("'{}': {}", p, val_repr));
        }
        let entries_str = if total > LIMIT {
            format!("{{{}, ...}}", pairs.join(", "))
        } else if pairs.is_empty() {
            "{}".to_string()
        } else {
            format!("{{{}}}", pairs.join(", "))
        };
        Ok(format!(
            "Pattrie({}, maxbits={}, family={})",
            entries_str, self.maxbits, family_name
        ))
    }

    fn __eq__(&self, py: Python<'_>, other: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let Ok(other_pattrie) = other.extract::<pyo3::PyRef<Pattrie>>() else {
            return Ok(py.NotImplemented());
        };

        let guard_self = self.inner.read().unwrap();
        let guard_other = other_pattrie.inner.read().unwrap();

        let eq = match (&*guard_self, &*guard_other) {
            (TrieInner::V4(m1), TrieInner::V4(m2)) => maps_equal(py, m1, m2)?,
            (TrieInner::V6(m1), TrieInner::V6(m2)) => maps_equal(py, m1, m2)?,
            _ => false, // different address families -> not equal
        };

        Ok(pyo3::types::PyBool::new(py, eq).to_owned().into_any().unbind())
    }

    fn __hash__(&self) -> PyResult<isize> {
        // Mutable container, like dict/list — unhashable so that the
        // hash/eq invariant (equal objects hash equal) is never violated.
        Err(PyTypeError::new_err("unhashable type: 'Pattrie'"))
    }

    #[pyo3(signature = (key_or_addr, value_or_prefixlen, value=None))]
    fn insert(
        &self,
        py: Python<'_>,
        key_or_addr: &Bound<'_, PyAny>,
        value_or_prefixlen: &Bound<'_, PyAny>,
        value: Option<Py<PyAny>>,
    ) -> PyResult<()> {
        check_mutable(self.frozen)?;

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
            if (self.family == self.af_inet) != is_v4 {
                return Err(PyValueError::new_err("Address family mismatch"));
            }
            (net, v)
        } else {
            // 2-arg form: insert(prefix, value)
            let net = parse_network_key(py, key_or_addr, self.family, self.af_inet)?;
            (net, value_or_prefixlen.clone().unbind())
        };

        validate_prefix_len(net.prefix_len(), self.maxbits)?;

        let mut guard = self.inner.write().unwrap();
        guard.insert(net, val);
        Ok(())
    }

    fn insert_many(&self, py: Python<'_>, items: &Bound<'_, PyAny>) -> PyResult<()> {
        check_mutable(self.frozen)?;

        let mut entries: Vec<(IpNet, Py<PyAny>)> = Vec::new();
        for item_result in items.try_iter()? {
            let item = item_result?;
            let seq = item.cast::<PySequence>().map_err(|_| {
                PyValueError::new_err("Expected (prefix, value) pair, got non-sequence")
            })?;
            let len = seq.len()?;
            if len != 2 {
                return Err(PyValueError::new_err(format!(
                    "Expected (prefix, value) pair, got sequence of length {}",
                    len
                )));
            }
            let key = seq.get_item(0)?;
            let value: Py<PyAny> = seq.get_item(1)?.unbind();
            let net = parse_network_key(py, &key, self.family, self.af_inet)?;
            validate_prefix_len(net.prefix_len(), self.maxbits)?;
            entries.push((net, value));
        }

        // Parsing above needs the GIL for PyObject access; the trie write does not.
        let inner_arc = Arc::clone(&self.inner);
        py.detach(move || {
            let mut guard = inner_arc.write().unwrap();
            for (net, val) in entries {
                guard.insert(net, val);
            }
        });

        Ok(())
    }

    fn __iter__(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let keys = self.keys(false);
        let list = pyo3::types::PyList::new(py, &keys)?;
        Ok(list.call_method0("__iter__")?.unbind())
    }

    #[pyo3(signature = (bare=false))]
    fn keys(&self, bare: bool) -> Vec<String> {
        let guard = self.inner.read().unwrap();
        let full: Vec<String> = match &*guard {
            TrieInner::V4(map) => map.iter().map(|(p, _)| p.to_string()).collect(),
            TrieInner::V6(map) => map.iter().map(|(p, _)| p.to_string()).collect(),
        };
        if bare { full.iter().map(|s| to_bare_addr(s)).collect() } else { full }
    }

    fn values(&self, py: Python<'_>) -> Vec<Py<PyAny>> {
        let guard = self.inner.read().unwrap();
        match &*guard {
            TrieInner::V4(map) => collect_values(map, py),
            TrieInner::V6(map) => collect_values(map, py),
        }
    }

    #[pyo3(signature = (bare=false))]
    fn items(&self, py: Python<'_>, bare: bool) -> PyResult<Vec<Py<PyAny>>> {
        let guard = self.inner.read().unwrap();
        let pairs = match &*guard {
            TrieInner::V4(map) => collect_items(map, py),
            TrieInner::V6(map) => collect_items(map, py),
        };
        pairs.into_iter().map(|(k, v)| {
            let key_str = format_key(&k, bare);
            PyTuple::new(py, [PyString::new(py, &key_str).into_any().unbind(), v])
                .map(|t| t.into_any().unbind())
        }).collect()
    }

    #[pyo3(signature = (prefix, bare=false))]
    fn children(&self, py: Python<'_>, prefix: &Bound<'_, PyAny>, bare: bool) -> PyResult<Vec<String>> {
        let af_inet = self.af_inet;
        let net = parse_network_key(py, prefix, self.family, af_inet)?;

        let guard = self.inner.read().unwrap();
        let full = match (&*guard, net) {
            (TrieInner::V4(map), IpNet::V4(v4)) => find_children(map, &v4),
            (TrieInner::V6(map), IpNet::V6(v6)) => find_children(map, &v6),
            _ => unreachable!(),
        };
        Ok(if bare { full.iter().map(|s| to_bare_addr(s)).collect() } else { full })
    }

    #[pyo3(signature = (prefix, bare=false))]
    fn parent(&self, py: Python<'_>, prefix: &Bound<'_, PyAny>, bare: bool) -> PyResult<Option<String>> {
        let af_inet = self.af_inet;
        let net = parse_network_key(py, prefix, self.family, af_inet)?;

        let guard = self.inner.read().unwrap();
        let full = match (&*guard, net) {
            (TrieInner::V4(map), IpNet::V4(v4)) => find_parent(map, &v4),
            (TrieInner::V6(map), IpNet::V6(v6)) => find_parent(map, &v6),
            _ => unreachable!(),
        };
        Ok(full.map(|s| format_key(&s, bare)))
    }

    fn get_all(&self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<Vec<Py<PyAny>>> {
        let af_inet = self.af_inet;
        let net = parse_key(py, key, self.family, af_inet)?;

        let guard = self.inner.read().unwrap();
        match (&*guard, &net) {
            (TrieInner::V4(map), IpNet::V4(v4)) => collect_covering_items(map, v4, py),
            (TrieInner::V6(map), IpNet::V6(v6)) => collect_covering_items(map, v6, py),
            _ => unreachable!(),
        }
    }

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
            // Phase 1: extract all keys into owned Option<FrozenKey> while holding the GIL.
            // Order: PyString first (zero-copy), raw bytes second (must precede str() fallback
            // or bytes repr would stringify to e.g. "b'\\n\\x01\\x02\\x03'" and be lost),
            // then str() fallback for ipaddress objects, ints, etc. None for anything invalid.
            let mut frozen_keys: Vec<Option<FrozenKey>> = Vec::with_capacity(n);
            for item in keys.iter() {
                let fk = if let Ok(py_str) = item.cast::<PyString>() {
                    py_str.to_str().map(|s| FrozenKey::Str(s.to_owned())).ok()
                } else if let Some((raw, plen)) = extract_raw_bytes_like(&item) {
                    Some(FrozenKey::Raw(raw, plen))
                } else {
                    item.str().and_then(|ps| ps.to_str().map(|s| s.to_owned()))
                        .map(FrozenKey::Str).ok()
                };
                frozen_keys.push(fk);
            }

            let inner_arc = Arc::clone(&self.inner);
            let family = self.family;
            let af_inet = self.af_inet;

            // Phase 2: all trie traversals without the GIL (pure Rust on owned data).
            let matched: Vec<Option<IpNet>> = py.detach(|| {
                let guard = inner_arc.read().unwrap();
                frozen_keys.iter().map(|fk| {
                    let fk = fk.as_ref()?;
                    let net = match fk {
                        FrozenKey::Str(s) => parse_key_from_str(s, family, af_inet).ok()?,
                        FrozenKey::Raw(raw, plen) => net_from_octets(raw, *plen, family, af_inet).ok()?,
                    };
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

    fn dump(&self, py: Python<'_>, path: std::path::PathBuf) -> PyResult<()> {
        if !self.frozen {
            return Err(PyValueError::new_err("dump() requires a frozen trie; call freeze() first"));
        }

        // Collect entries (addr bytes + prefixlen) and Python values in trie order.
        let (addr_entries, values): (Vec<(Vec<u8>, u8)>, Vec<Py<PyAny>>) = {
            let guard = self.inner.read().unwrap();
            match &*guard {
                TrieInner::V4(map) => map.iter().map(|(p, v)| {
                    ((p.network().octets().to_vec(), p.prefix_len()), v.clone_ref(py))
                }).unzip(),
                TrieInner::V6(map) => map.iter().map(|(p, v)| {
                    ((p.network().octets().to_vec(), p.prefix_len()), v.clone_ref(py))
                }).unzip(),
            }
        };

        // Pickle the values as a Python list.
        let pickle = py.import("pickle")?;
        let values_list = PyList::new(py, &values)?;
        let pickled: Vec<u8> = pickle.call_method1("dumps", (values_list,))?.extract()?;

        // Build fixed-size entry records.
        let entry_size: usize = if self.family == self.af_inet { 5 } else { 17 };
        let entry_count = addr_entries.len() as u64;
        let values_offset = 32u64 + entry_count * entry_size as u64;

        let mut entries_bytes: Vec<u8> = Vec::with_capacity(addr_entries.len() * entry_size);
        for (addr, prefixlen) in &addr_entries {
            entries_bytes.extend_from_slice(addr);
            entries_bytes.push(*prefixlen);
        }

        let mut f = std::fs::File::create(&path)
            .map_err(|e| PyValueError::new_err(format!("Cannot create {:?}: {e}", path)))?;
        f.write_all(b"PTRI").map_err(|e| PyValueError::new_err(e.to_string()))?;
        f.write_all(&1u32.to_le_bytes()).map_err(|e| PyValueError::new_err(e.to_string()))?;
        f.write_all(&(self.family as u32).to_le_bytes()).map_err(|e| PyValueError::new_err(e.to_string()))?;
        f.write_all(&(self.maxbits as u32).to_le_bytes()).map_err(|e| PyValueError::new_err(e.to_string()))?;
        f.write_all(&entry_count.to_le_bytes()).map_err(|e| PyValueError::new_err(e.to_string()))?;
        f.write_all(&values_offset.to_le_bytes()).map_err(|e| PyValueError::new_err(e.to_string()))?;
        f.write_all(&entries_bytes).map_err(|e| PyValueError::new_err(e.to_string()))?;
        f.write_all(&pickled).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(())
    }

    #[classmethod]
    fn load(_cls: &Bound<'_, PyType>, py: Python<'_>, path: std::path::PathBuf) -> PyResult<Py<Self>> {
        use memmap2::Mmap;

        let file = std::fs::File::open(&path)
            .map_err(|e| PyValueError::new_err(format!("Cannot open {:?}: {e}", path)))?;
        // SAFETY: we only read from the mapping and drop it before returning.
        let mmap = unsafe { Mmap::map(&file) }
            .map_err(|e| PyValueError::new_err(format!("mmap failed: {e}")))?;

        if mmap.len() < 32 {
            return Err(PyValueError::new_err("File too small to be a valid pattrie dump"));
        }
        if &mmap[0..4] != b"PTRI" {
            return Err(PyValueError::new_err("Not a pattrie dump file (bad magic)"));
        }
        let version     = u32::from_le_bytes(mmap[4..8].try_into().unwrap());
        if version != 1 {
            return Err(PyValueError::new_err(format!("Unsupported dump version: {version}")));
        }
        let family      = u32::from_le_bytes(mmap[8..12].try_into().unwrap()) as i32;
        let maxbits     = u32::from_le_bytes(mmap[12..16].try_into().unwrap()) as u8;
        let entry_count = u64::from_le_bytes(mmap[16..24].try_into().unwrap()) as usize;
        let values_off  = u64::from_le_bytes(mmap[24..32].try_into().unwrap()) as usize;

        let socket  = py.import("socket")?;
        let af_inet: i32 = socket.getattr("AF_INET")?.extract()?;
        let entry_size: usize = if family == af_inet { 5 } else { 17 };

        let expected_values_off = 32 + entry_count * entry_size;
        if values_off != expected_values_off || mmap.len() < values_off {
            return Err(PyValueError::new_err("Corrupt dump file (bad offsets)"));
        }

        // Unpickle values list.
        let pickle  = py.import("pickle")?;
        let pickle_bytes: &[u8] = &mmap[values_off..];
        let values_obj = pickle.call_method1("loads", (pickle_bytes,))?;
        let values = values_obj.cast::<PyList>()?;
        if values.len() != entry_count {
            return Err(PyValueError::new_err("Corrupt dump file (entry/value count mismatch)"));
        }

        // Reconstruct the trie from fixed-size entry records.
        let mut inner = if family == af_inet {
            TrieInner::V4(PrefixMap::new())
        } else {
            TrieInner::V6(PrefixMap::new())
        };

        for i in 0..entry_count {
            let off = 32 + i * entry_size;
            let value: Py<PyAny> = values.get_item(i)?.unbind();
            if family == af_inet {
                let octets: [u8; 4] = mmap[off..off + 4].try_into().unwrap();
                let prefixlen = mmap[off + 4];
                let net = Ipv4Net::new(std::net::Ipv4Addr::from(octets), prefixlen)
                    .map_err(|e| PyValueError::new_err(e.to_string()))?;
                if let TrieInner::V4(ref mut map) = inner { map.insert(net, value); }
            } else {
                let octets: [u8; 16] = mmap[off..off + 16].try_into().unwrap();
                let prefixlen = mmap[off + 16];
                let net = Ipv6Net::new(std::net::Ipv6Addr::from(octets), prefixlen)
                    .map_err(|e| PyValueError::new_err(e.to_string()))?;
                if let TrieInner::V6(ref mut map) = inner { map.insert(net, value); }
            }
        }

        // mmap and file are dropped here — unmapped before we return.
        drop(mmap);
        drop(file);

        Py::new(py, Pattrie {
            inner: Arc::new(RwLock::new(inner)),
            maxbits,
            family,
            af_inet,
            frozen: true,
        })
    }

    fn add(&mut self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<()> {
        check_mutable(self.frozen)?;
        let net = parse_network_key(py, key, self.family, self.af_inet)?;
        validate_prefix_len(net.prefix_len(), self.maxbits)?;

        let mut guard = self.inner.write().unwrap();
        // Only insert if not already present — never clobber an existing value.
        let exists = match (&*guard, &net) {
            (TrieInner::V4(map), IpNet::V4(v4)) => map.contains_key(v4),
            (TrieInner::V6(map), IpNet::V6(v6)) => map.contains_key(v6),
            _ => unreachable!(),
        };
        if !exists {
            guard.insert(net, py.None());
        }
        Ok(())
    }

    fn discard(&mut self, _py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<()> {
        check_mutable(self.frozen)?;
        let net = parse_network_key(_py, key, self.family, self.af_inet)?;
        validate_prefix_len(net.prefix_len(), self.maxbits)?;

        let mut guard = self.inner.write().unwrap();
        match (&mut *guard, net) {
            (TrieInner::V4(map), IpNet::V4(v4)) => { map.remove(&v4); }
            (TrieInner::V6(map), IpNet::V6(v6)) => { map.remove(&v6); }
            _ => unreachable!(),
        }
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

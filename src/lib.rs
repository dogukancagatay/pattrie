use pyo3::prelude::*;
use pyo3::exceptions::{PyKeyError, PyValueError};
use prefix_trie::PrefixMap;
use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};

enum TrieInner {
    V4(PrefixMap<Ipv4Net, Py<PyAny>>),
    V6(PrefixMap<Ipv6Net, Py<PyAny>>),
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
}

#[pymodule]
fn _pattrie(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyTricia>()?;
    Ok(())
}

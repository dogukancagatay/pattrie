use pyo3::prelude::*;

#[pymodule]
fn pattrie(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    Ok(())
}

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;

#[derive(Debug)]
pub(crate) struct B64Error;

pub(crate) fn encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub(crate) fn decode(value: &str) -> Result<Vec<u8>, B64Error> {
    STANDARD
        .decode(value)
        .or_else(|_| STANDARD_NO_PAD.decode(value))
        .map_err(|_| B64Error)
}

pub(crate) fn decode_array<const N: usize>(value: &str) -> Result<[u8; N], B64Error> {
    let bytes = decode(value.trim())?;
    if bytes.len() != N {
        return Err(B64Error);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

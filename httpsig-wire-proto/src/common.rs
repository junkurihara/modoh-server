use super::error::HttpSigError;
use bytes::{Buf, BufMut, Bytes, BytesMut};

/* ------------------------------------------- */
// Imported from odoh-rs crate

/// Serialize to IETF wireformat that is similar to [XDR](https://tools.ietf.org/html/rfc1014)
pub(super) trait Serialize {
  type Error;
  /// Serialize the provided struct into the buf.
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), Self::Error>;
}

/// Deserialize from IETF wireformat that is similar to [XDR](https://tools.ietf.org/html/rfc1014)
pub(super) trait Deserialize {
  type Error;
  /// Deserialize a struct from the buf.
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, Self::Error>
  where
    Self: Sized;
}

/// Convenient function to deserialize a structure from Bytes.
pub(super) fn parse<D: Deserialize, B: Buf>(buf: &mut B) -> Result<D, D::Error> {
  D::deserialize(buf)
}

#[allow(unused)]
/// Convenient function to serialize a structure into a new BytesMut.
pub(super) fn compose<S: Serialize>(s: S) -> Result<BytesMut, S::Error> {
  let mut buf = BytesMut::new();
  s.serialize(&mut buf)?;
  Ok(buf)
}

pub(super) fn read_lengthed<B: Buf>(b: &mut B) -> Result<Bytes, HttpSigError> {
  if b.remaining() < 2 {
    return Err(HttpSigError::ShortInput);
  }

  let len = b.get_u16() as usize;

  if len > b.remaining() {
    return Err(HttpSigError::InvalidInputLength);
  }

  Ok(b.copy_to_bytes(len))
}

#[inline]
pub(super) fn to_u16(n: usize) -> Result<u16, HttpSigError> {
  n.try_into().map_err(|_| HttpSigError::InvalidInputLength)
}

use crate::error::*;
use jwt_simple::prelude::*;
use spki::{der::Decode, Document, SubjectPublicKeyInfoRef};

#[allow(non_upper_case_globals)]
/// Algorithm OIDs
mod algorithm_oids {
  /// OID for `id-ecPublicKey`, if you're curious
  pub const EC: &str = "1.2.840.10045.2.1";
  /// OID for `id-Ed25519`, if you're curious
  pub const Ed25519: &str = "1.3.101.112";
}
#[allow(non_upper_case_globals)]
/// Params OIDs
mod params_oids {
  // Example parameters value: OID for the NIST P-256 elliptic curve.
  pub const Prime256v1: &str = "1.2.840.10045.3.1.7";
}

#[derive(Clone)]
/// Validation key for JWT
pub enum ValidationKey {
  EdDSA(Ed25519PublicKey),
  ES256(ES256PublicKey),
}

impl ValidationKey {
  /// Convert from pem string
  pub fn from_pem(pem: &str) -> Result<Self> {
    let (_s, doc) = Document::from_pem(pem)?;
    let alg = SubjectPublicKeyInfoRef::from_der(doc.as_bytes())?.algorithm;
    match alg.oid.to_string().as_ref() {
      // ec
      algorithm_oids::EC => {
        let param = alg.parameters_oid()?;
        match param.to_string().as_ref() {
          // prime256v1 = es256
          params_oids::Prime256v1 => {
            let key = ES256PublicKey::from_pem(pem)?;
            Ok(Self::ES256(key))
          }
          _ => Err(RelayError::UnsupportedValidationKey),
        }
      }
      // ed25519
      algorithm_oids::Ed25519 => {
        let key = Ed25519PublicKey::from_pem(pem)?;
        Ok(Self::EdDSA(key))
      }
      _ => Err(RelayError::UnsupportedValidationKey),
    }
  }

  /// Verify JWT
  pub fn verify(&self, token: &str, opt: Option<&VerificationOptions>) -> Result<JWTClaims<NoCustomClaims>> {
    match self {
      Self::EdDSA(key) => {
        let c = key.verify_token(token, opt.cloned())?;
        Ok(c)
      }
      Self::ES256(key) => {
        let c = key.verify_token(token, opt.cloned())?;
        Ok(c)
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_es256() -> std::result::Result<(), anyhow::Error> {
    let pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERmLDHtAk+qSMqcEb6CZSzbOPnE4d\nii+31DW+YulmysZKQKDvuk96TARuWMO/vDbhk777a2QF3bgNoIj8UPMwnw==\n-----END PUBLIC KEY-----\n";
    let id_token="eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2OTkyODcxNzYsImV4cCI6MTY5OTI4ODk3NiwibmJmIjoxNjk5Mjg3MTc2LCJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20vdjEuMCIsInN1YiI6ImI2MjZmNTBlLTllYWUtNDlkOC04MjAxLTBhZmQyODNhZWNmZCIsImF1ZCI6WyJjbGllbnRfaWQxIl0sImlzX2FkbWluIjpmYWxzZX0.mmNxox_4nabjrlm-3AjDVX9U_tkQEKH5iHw3KSj22WnsmP4pKDEgZnVSWlxg3prLSfJZCfD3ZR1iiq6EFke45w";

    let vk = ValidationKey::from_pem(pem)?;
    assert!(matches!(vk, ValidationKey::ES256(_)));

    let mut iss = std::collections::HashSet::new();
    iss.insert("https://auth.example.com/v1.0".to_string());
    let mut aud = std::collections::HashSet::new();
    aud.insert("client_id1".to_string());
    let vo = VerificationOptions {
      artificial_time: Some(Duration::from_secs(1699286705)),
      allowed_issuers: Some(iss),
      allowed_audiences: Some(aud),
      ..Default::default()
    };
    let _res = vk.verify(id_token, Some(&vo))?;

    Ok(())
  }
  #[test]
  fn test_ed25519() -> std::result::Result<(), anyhow::Error> {
    let pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA1ixMQcxO46PLlgQfYS46ivFd+n0CcDHSKUnuhm3i1O0=\n-----END PUBLIC KEY-----\n";
    let id_token: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2OTkyODYzNjgsImV4cCI6MTY5OTI4ODE2OCwibmJmIjoxNjk5Mjg2MzY4LCJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20vdjEuMCIsInN1YiI6IjZiYmI2NGVhLTMyZmUtNGEyNi05MjhlLWZlODlmNTcxNTA0YiIsImF1ZCI6WyJjbGllbnRfaWQxIl0sImlzX2FkbWluIjpmYWxzZX0.e6D156U4pwalnWmZNK5fDBSjUDflmHQObAiHJLPYu7AS-x81RlO3sRsNoqHz47m0zxOBEFVA3esV74U6xwkyAw";

    let vk = ValidationKey::from_pem(pem)?;
    assert!(matches!(vk, ValidationKey::EdDSA(_)));

    let mut iss = std::collections::HashSet::new();
    iss.insert("https://auth.example.com/v1.0".to_string());
    let mut aud = std::collections::HashSet::new();
    aud.insert("client_id1".to_string());
    let vo = VerificationOptions {
      artificial_time: Some(Duration::from_secs(1699286705)),
      allowed_issuers: Some(iss),
      allowed_audiences: Some(aud),
      ..Default::default()
    };
    let _res = vk.verify(id_token, Some(&vo))?;

    Ok(())
  }
}

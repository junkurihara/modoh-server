use crate::{error::*, log::*};
use base64::{engine::general_purpose, Engine as _};
use jwt_simple::prelude::*;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use spki::{der::Decode, Document, SubjectPublicKeyInfoRef};

#[allow(non_upper_case_globals, dead_code)]
/// Algorithm OIDs
mod algorithm_oids {
  /// OID for `id-ecPublicKey`, if you're curious
  pub const EC: &str = "1.2.840.10045.2.1";
  /// OID for `id-Ed25519`, if you're curious
  pub const Ed25519: &str = "1.3.101.112";
}
#[allow(non_upper_case_globals, dead_code)]
/// Params OIDs
mod params_oids {
  // Example parameters value: OID for the NIST P-256 elliptic curve.
  pub const Prime256v1: &str = "1.2.840.10045.3.1.7";
}

/// Params JWK
mod params_jwk {
  /// Key type
  pub mod kty {
    pub const EC: &str = "EC";
    pub const OKP: &str = "OKP";
  }
  /// Curve
  pub mod crv {
    pub const P256: &str = "P-256";
    #[allow(non_upper_case_globals)]
    pub const Ed25519: &str = "Ed25519";
  }
}

#[derive(Clone)]
/// Validation key for JWT
pub enum ValidationKey {
  EdDSA(Ed25519PublicKey),
  ES256(ES256PublicKey),
}

impl ValidationKey {
  #[allow(dead_code)]
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
  /// Convert from jwk
  pub fn from_jwk(jwk: &serde_json::Value) -> Result<Self> {
    let mut jwk_clone = jwk.clone();
    let Some(jwk_map) = jwk_clone.as_object_mut() else {
      return Err(RelayError::UnsupportedValidationKey);
    };
    jwk_map.remove_entry("kid");
    let Ok(jwk_string) = serde_json::to_string(jwk_map) else {
      return Err(RelayError::UnsupportedValidationKey);
    };
    let kty = jwk
      .get("kty")
      .map(|v| v.as_str())
      .and_then(|v| v)
      .ok_or(RelayError::UnsupportedValidationKey)?;
    match kty {
      // ecdsa case
      params_jwk::kty::EC => {
        let crv = jwk
          .get("crv")
          .map(|v| v.as_str())
          .and_then(|v| v)
          .ok_or(RelayError::UnsupportedValidationKey)?;
        match crv {
          params_jwk::crv::P256 => {
            let pk = p256::PublicKey::from_jwk_str(&jwk_string).map_err(|e| {
              error!("Failed to parse jwk {:?}", e);
              RelayError::UnsupportedValidationKey
            })?;
            let sec1key = pk.to_encoded_point(false);
            let inner = ES256PublicKey::from_bytes(sec1key.as_bytes())?;
            Ok(ValidationKey::ES256(inner))
          }
          _ => Err(RelayError::UnsupportedValidationKey),
        }
      }
      params_jwk::kty::OKP => {
        let crv = jwk
          .get("crv")
          .map(|v| v.as_str())
          .and_then(|v| v)
          .ok_or(RelayError::UnsupportedValidationKey)?;
        match crv {
          params_jwk::crv::Ed25519 => {
            let Some(x) = jwk.get("x") else {
              return Err(RelayError::UnsupportedValidationKey);
            };
            let x = x.as_str().unwrap_or("");
            let x = general_purpose::URL_SAFE_NO_PAD.decode(x).map_err(|e| {
              error!("Failed to parse jwk {:?}", e);
              RelayError::UnsupportedValidationKey
            })?;
            let inner = Ed25519PublicKey::from_bytes(x.as_slice())?;
            Ok(ValidationKey::EdDSA(inner))
          }
          _ => Err(RelayError::UnsupportedValidationKey),
        }
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
  fn test_es256_pem() -> std::result::Result<(), anyhow::Error> {
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
  fn test_es256_jwk() -> std::result::Result<(), anyhow::Error> {
    let jwk =  "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"RmLDHtAk-qSMqcEb6CZSzbOPnE4dii-31DW-YulmysY\",\"y\":\"SkCg77pPekwEbljDv7w24ZO--2tkBd24DaCI_FDzMJ8\"}";
    let id_token= "eyJhbGciOiJFUzI1NiIsImtpZCI6ImszNHIzTnFmYWs2N2JoSlNYVGpUUm81dENJcjFCc3JlMWNQb0ozTEo5eEUiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE2OTk2MjYxMjIsImV4cCI6MTY5OTYyNzkyMiwibmJmIjoxNjk5NjI2MTIyLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvdjEuMCIsInN1YiI6IjZhMDJlNTRiLTk3NGEtNDViYy04ZDlhLWZhYzQzNzdhMDQ5MiIsImF1ZCI6WyJjbGllbnRfaWQxIl0sImlzX2FkbWluIjp0cnVlfQ.6O6wBd51zO-wZv7Y5r99NSqbEXg1XZtjhCW_FtvScZ8sPIOiU8GTHMfPxVriDyhiAC_W7NEOMZx-4myIeDiZCA";

    let jwk_val = serde_json::from_str::<serde_json::Value>(jwk)?;
    let vk = ValidationKey::from_jwk(&jwk_val)?;

    let mut iss = std::collections::HashSet::new();
    iss.insert("http://localhost:3000/v1.0".to_string());
    let mut aud = std::collections::HashSet::new();
    aud.insert("client_id1".to_string());
    let vo = VerificationOptions {
      artificial_time: Some(Duration::from_secs(1699626347)),
      allowed_issuers: Some(iss),
      allowed_audiences: Some(aud),
      ..Default::default()
    };
    let _res = vk.verify(id_token, Some(&vo))?;

    Ok(())
  }
  #[test]
  fn test_ed25519_pem() -> std::result::Result<(), anyhow::Error> {
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

  #[test]
  fn test_ed25519_jwk() -> std::result::Result<(), anyhow::Error> {
    let jwk = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"1ixMQcxO46PLlgQfYS46ivFd-n0CcDHSKUnuhm3i1O0\"}";
    let id_token= "eyJhbGciOiJFZERTQSIsImtpZCI6ImdqckU3QUNNeGd6WWZGSGdhYmdmNGtMVGcxZUtJZHNKOTRBaUZURmoxaXMiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE2OTk2MjYxMjUsImV4cCI6MTY5OTYyNzkyNSwibmJmIjoxNjk5NjI2MTI1LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvdjEuMCIsInN1YiI6ImY2ZDMzNmVlLWFjNDgtNGNlYy04MTYzLTI5OThlMTc4YWVlMyIsImF1ZCI6WyJjbGllbnRfaWQxIl0sImlzX2FkbWluIjp0cnVlfQ.GVJhFknZP5iWe0fKoUJO-Wfg1Ti0ayb7mjUEWvfYhQXwM_dYt39nICiebLEQr3vqctxdyKO8PlXxFpe9bI6bCg";

    let jwk_val = serde_json::from_str::<serde_json::Value>(jwk)?;
    let vk = ValidationKey::from_jwk(&jwk_val)?;

    let mut iss = std::collections::HashSet::new();
    iss.insert("http://localhost:3000/v1.0".to_string());
    let mut aud = std::collections::HashSet::new();
    aud.insert("client_id1".to_string());
    let vo = VerificationOptions {
      artificial_time: Some(Duration::from_secs(1699626347)),
      allowed_issuers: Some(iss),
      allowed_audiences: Some(aud),
      ..Default::default()
    };
    let _res = vk.verify(id_token, Some(&vo))?;
    Ok(())
  }
}

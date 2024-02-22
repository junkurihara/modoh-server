/* ------------------------------------------- */
#[derive(Clone, Default, Debug, PartialEq, Eq)]
/// Public key types used for httpsig's public-key-based signature.
pub enum HttpSigPkTypes {
  #[default]
  /// ed25519
  Ed25519,
  /// es256/ecdsa-p256-sha256
  EcdsaP256Sha256,
}

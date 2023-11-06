mod jwt;

pub use jwt::ValidationKey;

pub struct Authenticator {
  token_authenticator: Option<ValidationKey>,
  location_authenticator: Option<()>,
}

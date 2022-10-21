use std::fmt::{Display, Formatter};

use sp_core::crypto::SecretStringError;
use sp_core::ecdsa::DeriveError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NoirError {
  Bip39Error { message: String },
  EcdsaError { message: String },
}

impl Display for NoirError {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    match self {
      NoirError::Bip39Error { message } => write!(f, "{}", message),
      NoirError::EcdsaError { message } => write!(f, "{}", message),
    }
  }
}

impl From<bip39::ErrorKind> for NoirError {
  fn from(error: bip39::ErrorKind) -> Self {
    NoirError::Bip39Error { message: error.to_string() }
  }
}

impl From<SecretStringError> for NoirError {
  fn from(error: SecretStringError) -> Self {
    let message = match error {
      SecretStringError::InvalidFormat => "The overall format was invalid (e.g. the seed phrase contained symbols).".to_string(),
      SecretStringError::InvalidPhrase => "The seed phrase provided is not a valid BIP39 phrase.".to_string(),
      SecretStringError::InvalidPassword => "The supplied password was invalid.".to_string(),
      SecretStringError::InvalidSeed => "The seed is invalid (bad content).".to_string(),
      SecretStringError::InvalidSeedLength => "The seed has an invalid length.".to_string(),
      SecretStringError::InvalidPath => "The derivation path was invalid (e.g. contains soft junctions when they are not supported).".to_string()
    };
    NoirError::EcdsaError { message }
  }
}

impl From<DeriveError> for NoirError {
  fn from(error: DeriveError) -> Self {
    let message = match error {
      DeriveError::SoftKeyInPath => { "A soft key was found in the path (and is unsupported).".to_string() }
    };
    NoirError::EcdsaError { message }
  }
}

impl From<bitcoin::util::bip32::Error> for NoirError {
  fn from(error: bitcoin::util::bip32::Error) -> Self {
    NoirError::EcdsaError { message: error.to_string() }
  }
}

impl From<anyhow::Error> for NoirError {
  fn from(error: anyhow::Error) -> Self {
    NoirError::EcdsaError { message: error.to_string() }
  }
}

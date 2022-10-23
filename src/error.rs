use std::fmt::{Display, Formatter};

use bitcoin::bech32;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NoirError {
  Bip39Error { message: String },
  EcdsaError { message: String },
  Bech32Error { message: String },
}

impl Display for NoirError {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    match self {
      NoirError::Bip39Error { message } => write!(f, "{}", message),
      NoirError::EcdsaError { message } => write!(f, "{}", message),
      NoirError::Bech32Error { message } => write!(f, "{}", message),
    }
  }
}

impl From<bip39::ErrorKind> for NoirError {
  fn from(error: bip39::ErrorKind) -> Self {
    NoirError::Bip39Error { message: error.to_string() }
  }
}

impl From<bitcoin::util::bip32::Error> for NoirError {
  fn from(error: bitcoin::util::bip32::Error) -> Self {
    NoirError::EcdsaError { message: error.to_string() }
  }
}

impl From<bitcoin::secp256k1::Error> for NoirError {
  fn from(error: bitcoin::secp256k1::Error) -> Self {
    NoirError::EcdsaError { message: error.to_string() }
  }
}

impl From<bech32::Error> for NoirError {
  fn from(error: bech32::Error) -> Self {
    NoirError::Bech32Error { message: error.to_string() }
  }
}

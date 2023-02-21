use bitcoin::{
  bech32::{
    self, ToBase32, Variant::Bech32
  }, 
  secp256k1::PublicKey
};
use sp_core::keccak_256;

use crate::error::NoirError;

#[derive(PartialEq)]
pub struct Address(Vec<u8>);

impl Address {
  pub fn as_bytes(&self) -> Vec<u8> {
    self.0.clone()
  }

  pub fn from_public(public: &[u8]) -> Result<Self, NoirError> {
    let public = PublicKey::from_slice(public)?;
    let keccak256ed = keccak_256(&public.serialize_uncompressed()[1..]);
    let address = &keccak256ed[12..];
    Ok(Self(address.to_vec()))
  }

  pub fn to_string(&self, hrp: &str) -> Result<String, NoirError> {
    let data = self.0.as_slice();
    let base32ed = data.to_base32();
    let address = bech32::encode(hrp, base32ed, Bech32)?;
    Ok(address)
  }
}

#[cfg(test)]
mod tests {
  use crate::{ecdsa::KeyPair, evmos};

  #[test]
  fn evmos_address_test() {
    let mnemonic = "buffalo squirrel angry will brain measure mechanic van adjust canyon theory burger".to_string();
    let keypair = KeyPair::from_mnemonic(&mnemonic).unwrap();
    let path = "m/44h/60h/0h/0/0".to_string();
    let derived = keypair.derive(&path).unwrap();
    let address = evmos::Address::from_public(derived.public.as_bytes().as_ref()).unwrap();
    assert_eq!(address.to_string("evmos").unwrap(), "evmos1jy4ukswna5krms4mcfrlzszlw6pkpxdlrg9ysc");
  }

  #[test]
  fn hrp_address_test() {
    let mnemonic = "buffalo squirrel angry will brain measure mechanic van adjust canyon theory burger".to_string();
    let keypair = KeyPair::from_mnemonic(&mnemonic).unwrap();
    let path = "m/44h/60h/0h/0/0".to_string();
    let derived = keypair.derive(&path).unwrap();
    let address = evmos::Address::from_public(derived.public.as_bytes().as_ref()).unwrap();
    assert_eq!(address.to_string("evmos").unwrap(), "evmos1jy4ukswna5krms4mcfrlzszlw6pkpxdlrg9ysc");
    assert_eq!(address.to_string("canto").unwrap(), "canto1jy4ukswna5krms4mcfrlzszlw6pkpxdlnl467c");
  }
}

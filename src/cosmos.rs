use bitcoin::bech32;
use bitcoin::bech32::ToBase32;
use bitcoin::bech32::Variant::Bech32;
use bitcoin::hashes::{Hash, ripemd160};
use bitcoin::psbt::serialize::Serialize;
use sp_core::hashing::sha2_256;

use crate::error::NoirError;

#[derive(PartialEq)]
pub struct Address {
  inner: Vec<u8>,
}

impl Address {
  pub fn as_bytes(&self) -> Vec<u8> {
    self.inner.clone()
  }

  pub fn from_public(public: &[u8]) -> Result<Self, NoirError> {
    let sha256ed = sha2_256(public);
    let address = ripemd160::Hash::hash(&sha256ed).serialize();

    Ok(Self {
      inner: address.to_owned()
    })
  }

  pub fn to_string(&self, hrp: &str) -> Result<String, NoirError> {
    let data = self.inner.as_slice();
    let base32ed = data.to_base32();
    let address = bech32::encode(hrp, base32ed, Bech32)?;
    Ok(address)
  }
}

#[cfg(test)]
mod tests {
  use crate::cosmos;
  use crate::ecdsa::KeyPair;

  #[test]
  fn cosmos_address_test() {
    let mnemonic = "faith like regret hard hood ball jump rely sad million october comic".to_string();
    let keypair = KeyPair::from_mnemonic(&mnemonic).unwrap();
    let path = "m/44'/118'/0'/0/0".to_string();
    let derived = keypair.derive(&path).unwrap();
    let address = cosmos::Address::from_public(derived.public.as_bytes().as_ref()).unwrap();
    assert_eq!(address.to_string("cosmos").unwrap(), "cosmos1evlxjlzenjqvc6ddeur20ftrhp27fsv98jxhpr");
  }

  #[test]
  fn hrp_address_test() {
    let mnemonic = "buffalo squirrel angry will brain measure mechanic van adjust canyon theory burger".to_string();
    let keypair = KeyPair::from_mnemonic(&mnemonic).unwrap();
    let path = "m/44'/118'/0'/0/0".to_string();
    let derived = keypair.derive(&path).unwrap();
    let address = cosmos::Address::from_public(derived.public.as_bytes().as_ref()).unwrap();
    assert_eq!(address.to_string("cosmos").unwrap(), "cosmos1hzuth7mwmaecq92r6kp4slfjvpk7a49j7s6n8e");
    assert_eq!(address.to_string("osmo").unwrap(), "osmo1hzuth7mwmaecq92r6kp4slfjvpk7a49jktfr3t");
    assert_eq!(address.to_string("juno").unwrap(), "juno1hzuth7mwmaecq92r6kp4slfjvpk7a49jgzegq9");
    assert_eq!(address.to_string("stars").unwrap(), "stars1hzuth7mwmaecq92r6kp4slfjvpk7a49j2vdwvg");
  }
}

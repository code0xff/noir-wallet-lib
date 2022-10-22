use bitcoin::secp256k1::PublicKey;
use sp_core::keccak_256;

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
    let public = PublicKey::from_slice(public)?;
    let keccak256ed = keccak_256(&public.serialize_uncompressed()[1..]);
    let sliced = &keccak256ed[12..];
    Ok(Self {
      inner: sliced.to_vec()
    })
  }

  pub fn to_string(&self) -> String {
    let address = hex::encode(self.inner.as_slice());
    let keccak256ed = hex::encode(keccak_256(address.as_bytes()));
    let mut result: Vec<char> = Vec::new();
    for (i, c) in address.chars().into_iter().enumerate() {
      if c >= 'a' && keccak256ed.chars().nth(i).unwrap() >= '8' {
        result.push(c.to_ascii_uppercase());
      } else {
        result.push(c);
      }
    }
    format!("0x{}", result.iter().collect::<String>())
  }
}

#[cfg(test)]
mod tests {
  use sp_core::keccak_256;

  use crate::ecdsa::KeyPair;
  use crate::eth::Address;

  #[test]
  fn text_keccak256_test() {
    let keccak256ed = keccak_256("7f7625faa1ca985e9ad678656a9dcdf79620df6b".as_bytes());

    assert_eq!(hex::encode(keccak256ed), "3015b5c87eeb15cce85e3e48eefb50b400dd497c7b0bd41f16937ead349b3784");
  }

  #[test]
  fn eth_address_test() {
    let mnemonic = "hammer afford nothing drastic news coil inform switch stool wet denial science".to_string();
    let keypair = KeyPair::from_mnemonic(&mnemonic).unwrap();
    let path = "m/44'/60'/0'/0/0".to_string();
    let derived = keypair.derive(&path).unwrap();
    let address = Address::from_public(&derived.public.as_bytes()).unwrap();

    assert_eq!(address.to_string(), "0x38e4A67366963f356f9834c04481ff65ca7A07a3");
  }
}

use bitcoin::hashes::{Hash, ripemd160};
use bitcoin::psbt::serialize::Serialize;
use bitcoin::util::base58;
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
    let sha256ed_public = sha2_256(public);
    let ripemd160ed = ripemd160::Hash::hash(&sha256ed_public).serialize();
    let mut address: [u8; 25] = [0; 25];
    address[1..21].clone_from_slice(&ripemd160ed);
    let sha256ed_network_added = sha2_256(&address[..21]);
    let checksum = sha2_256(&sha256ed_network_added)[..4].to_owned();
    address[21..].clone_from_slice(&checksum);

    Ok(Self {
      inner: address.to_vec()
    })
  }

  pub fn to_string(&self) -> String {
    base58::encode_slice(&self.inner)
  }
}

#[cfg(test)]
mod tests {
  use bitcoin::hashes::{Hash, ripemd160};
  use bitcoin::psbt::serialize::Serialize;
  use sp_core::hashing::sha2_256;
  use crate::btc;

  #[test]
  fn checksum_test() {
    let sha256ed = sha2_256(hex::decode("03CEDC3561402780F1345D5EC2C6B5CD18461347F2B1C4BCE9B4178368FC53CA6E").unwrap().as_slice());
    assert_eq!(hex::encode(sha256ed), "9B8936F0F8A55BC7043AFB230124252C41D28CC54BCAD7C582507DA241C27A4A".to_lowercase());

    let ripemd160ed = ripemd160::Hash::hash(&sha256ed).serialize();
    assert_eq!(hex::encode(ripemd160ed.as_slice()), "5599A6E100F77F0706AE153741159E5CFFECE1EB".to_lowercase());

    let mut address: [u8; 25] = [0; 25];
    address[1..21].clone_from_slice(&ripemd160ed);
    let sha256ed = sha2_256(&address[..21]);
    let checksum = sha2_256(&sha256ed)[..4].to_owned();
    assert_eq!(hex::encode(checksum.as_slice()), "DFE52B45".to_lowercase());
  }

  #[test]
  fn btc_address_test() {
    let public = hex::decode("03CEDC3561402780F1345D5EC2C6B5CD18461347F2B1C4BCE9B4178368FC53CA6E").unwrap();
    let address = btc::Address::from_public(&public).unwrap();
    assert_eq!(address.to_string(), "18ocWE2zNjuGegnWeDbBAPwrhmdzfX9XJL");
  }
}

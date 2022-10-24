pub mod error;
pub mod eth;
pub mod btc;
pub mod cosmos;

pub mod bip39 {
  use bip39::Seed;

  pub struct Mnemonic;

  impl Mnemonic {
    pub fn generate() -> (String, Vec<u8>) {
      let mnemonic = bip39::Mnemonic::new(bip39::MnemonicType::Words12, bip39::Language::English);
      let seed = Seed::new(&mnemonic, "");
      (mnemonic.into_phrase(), seed.as_bytes().to_vec())
    }
  }
}

pub mod ecdsa {
  use std::fmt::{Debug, Display, Formatter};
  use std::str::FromStr;

  use bip39::{Mnemonic, Seed};
  use bip39::Language::English;
  use bitcoin::Network;
  use bitcoin::secp256k1::Secp256k1;
  use bitcoin::util::base58;
  use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
  use serde::{Serialize, Serializer};

  use crate::error::NoirError;

  #[derive(Clone, Serialize)]
  pub struct KeyPair {
    pub seed: Vec<u8>,
    pub private: Private,
    pub public: Public,
    pub ext_private: Option<ExtendedPrivate>,
    pub ext_public: ExtendedPublic,
  }

  #[derive(Copy, Clone, Debug)]
  pub struct Private([u8; 32]);

  impl Display for Private {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
      write!(f, "0x{}", hex::encode(self.0.as_slice()))
    }
  }

  impl Serialize for Private {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
      serializer.serialize_str(self.to_string().as_ref())
    }
  }

  impl Private {
    pub fn as_bytes(&self) -> [u8; 32] {
      self.0.clone()
    }
  }

  #[derive(Copy, Clone, Debug)]
  pub struct ExtendedPrivate([u8; 78]);

  impl Display for ExtendedPrivate {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
      base58::check_encode_slice_to_fmt(f, self.0.as_slice())
    }
  }

  impl Serialize for ExtendedPrivate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
      serializer.serialize_str(self.to_string().as_ref())
    }
  }

  #[derive(Copy, Clone, Debug)]
  pub struct Public([u8; 33]);

  impl Display for Public {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
      write!(f, "0x{}", hex::encode(self.0.as_slice()))
    }
  }

  impl Serialize for Public {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
      serializer.serialize_str(self.to_string().as_ref())
    }
  }

  impl Public {
    pub fn as_bytes(&self) -> [u8; 33] {
      self.0.clone()
    }
  }

  #[derive(Copy, Clone, Debug)]
  pub struct ExtendedPublic([u8; 78]);

  impl Display for ExtendedPublic {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
      base58::check_encode_slice_to_fmt(f, self.0.as_slice())
    }
  }

  impl Serialize for ExtendedPublic {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
      serializer.serialize_str(self.to_string().as_ref())
    }
  }

  impl KeyPair {
    pub fn from_mnemonic(mnemonic: &str) -> Result<Self, NoirError> {
      let res = Mnemonic::from_phrase(mnemonic, English);
      match res {
        Ok(mnemonic) => {
          let seed = Seed::new(&mnemonic, "");
          Ok(Self::from_seed(seed.as_bytes())?)
        }
        Err(err) => {
          Err(NoirError::Bip39Error { message: err.to_string() })
        }
      }
    }

    pub fn from_seed(seed: &[u8]) -> Result<Self, NoirError> {
      let secp256k1 = Secp256k1::new();
      let master = ExtendedPrivKey::new_master(Network::Bitcoin, seed)?;
      let keypair = master.to_keypair(&secp256k1);
      let secp256k1 = Secp256k1::new();
      let master_public = ExtendedPubKey::from_priv(&secp256k1, &master);
      Ok(Self {
        seed: seed.to_vec(),
        private: Private(keypair.secret_bytes()),
        public: Public(keypair.public_key().serialize()),
        ext_private: Some(ExtendedPrivate(master.encode())),
        ext_public: ExtendedPublic(master_public.encode()),
      })
    }

    pub fn seed(&self) -> Vec<u8> {
      self.seed.clone()
    }

    pub fn derive(&self, path: &str) -> Result<Self, NoirError> {
      let master = ExtendedPrivKey::new_master(Network::Bitcoin, self.seed().as_ref())?;
      let secp256k1 = Secp256k1::new();
      let path = DerivationPath::from_str(path)?;
      let derived = master.derive_priv(&secp256k1, &path)?;
      let keypair = derived.to_keypair(&secp256k1);
      let secp256k1 = Secp256k1::new();
      let derived_public = ExtendedPubKey::from_priv(&secp256k1, &derived);
      Ok(Self {
        seed: self.seed.to_vec(),
        private: Private(keypair.secret_bytes()),
        public: Public(keypair.public_key().serialize()),
        ext_private: Some(ExtendedPrivate(derived.encode())),
        ext_public: ExtendedPublic(derived_public.encode()),
      })
    }
  }
}

#[cfg(test)]
mod tests {
  use crate::ecdsa::KeyPair;

  #[test]
  fn parse_path_test() {
    let keypair = KeyPair::from_mnemonic("hammer afford nothing drastic news coil inform switch stool wet denial science").unwrap();
    let derived = keypair.derive("m/44'/60'/0'/0/0").unwrap();

    assert_eq!(derived.private.to_string(), "0xd8f01ecf156f642a53f39c5ce47c03e237fd9118a67f9cf410ae8aee8dd7c6f5");
    assert_eq!(derived.public.to_string(), "0x03c15b6b6465953b57ba9b24cb7af04787fd45b07da23ad77afdd9ff76a60b4993");
  }

  #[test]
  fn extended_keys_test() {
    let mnemonic = "around rubber impulse hunt tube problem buffalo this gym chimney surge cliff";
    let master = KeyPair::from_mnemonic(mnemonic).unwrap();
    let master_priv = master.ext_private.unwrap();
    assert_eq!(master_priv.to_string(), "xprv9s21ZrQH143K4KTMS92J1GszW24isqe4ZDjZ9aQDmQK8SbiPTWFZ2HvNGbZmftDTnpZdaAGQN7nGRTzo647Ug8F8xioH71Mn2Vd29ENkeKC");

    let derived = master.derive("m/44'/0'/0'/0").unwrap();
    let derived_priv = derived.ext_private.unwrap();
    let derived_pub = derived.ext_public;
    assert_eq!(derived_priv.to_string(), "xprvA1WrsZWmGdBohiKzutdRNQDv1dr1VUzNPfvzCMK9KgTziJysMpShFyBzotMc77JLDcC1egXVRhGC4xcFsazgPkdyarPgTHopf1Y2aVQfYvA");
    assert_eq!(derived_pub.to_string(), "xpub6EWDH53f6zk6vCQU1vARjYAeZfgVtwiDktrazjikt1zyb7K1uMkwomWUf8GPmBbZeWk4eNRD83Cg1BT8767ed8ZpujdGCyfYPNRN9RZ9z5J");
  }

  #[test]
  fn keypair_serialize_test() {
    let mnemonic = "around rubber impulse hunt tube problem buffalo this gym chimney surge cliff";
    let keypair = KeyPair::from_mnemonic(mnemonic).unwrap();
    let json = serde_json::json!(keypair);
    println!("{}", json.to_string());
  }
}

pub mod error;

mod noir {
  pub mod crypto {
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
    use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey};

    use crate::error::NoirError;

    pub struct KeyPair {
      pub seed: Vec<u8>,
      pub private: Private,
      pub public: Public,
    }

    pub struct Private {
      inner: [u8; 32],
    }

    impl Display for Private {
      fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.inner.as_slice()))
      }
    }

    impl Debug for Private {
      fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x?}", self.inner)
      }
    }

    pub struct Public {
      inner: [u8; 33],
    }

    impl Display for Public {
      fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.inner.as_slice()))
      }
    }

    impl Debug for Public {
      fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x?}", self.inner)
      }
    }

    impl Public {
      pub fn as_bytes(&self) -> [u8; 33] {
        self.inner.clone()
      }
    }

    impl KeyPair {
      pub fn from_mnemonic(mnemonic: &String) -> Result<Self, NoirError> {
        let mnemonic = Mnemonic::from_phrase(mnemonic, English)?;
        let seed = Seed::new(&mnemonic, "");
        Self::from_seed(seed.as_bytes())
      }

      pub fn from_seed(seed: &[u8]) -> Result<Self, NoirError> {
        let secp256k1 = Secp256k1::new();
        let master = ExtendedPrivKey::new_master(Network::Bitcoin, seed)?;
        let keypair = master.to_keypair(&secp256k1);
        Ok(Self {
          seed: seed.to_vec(),
          private: Private { inner: keypair.secret_bytes() },
          public: Public { inner: keypair.public_key().serialize() },
        })
      }

      pub fn seed(&self) -> Vec<u8> {
        self.seed.clone()
      }

      pub fn derive(&self, path: &String) -> Result<Self, NoirError> {
        let root = ExtendedPrivKey::new_master(Network::Bitcoin, self.seed().as_ref())?;
        let secp256k1 = Secp256k1::new();
        let path = DerivationPath::from_str(path).unwrap();
        let derived = root.derive_priv(&secp256k1, &path)?;
        derived.chain_code;
        let keypair = derived.to_keypair(&secp256k1);
        Ok(Self {
          seed: self.seed.to_vec(),
          private: Private { inner: keypair.secret_bytes() },
          public: Public { inner: keypair.public_key().serialize() },
        })
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use crate::noir::crypto::Mnemonic;
  use crate::noir::ecdsa::KeyPair;

  #[test]
  fn generate_mnemonic_test() {
    let mnemonic = Mnemonic::generate();
    println!("{}", mnemonic.0);
  }

  #[test]
  fn parse_path_test() {
    let mnemonic = Mnemonic::generate();
    let keypair = KeyPair::from_mnemonic(&mnemonic.0).unwrap();
    let path = "m/44'/0'/0'/0/0".to_string();
    let derived = keypair.derive(&path).unwrap();
    println!("{}", mnemonic.0);
    println!("{}", derived.private);
    println!("{}", derived.public);
  }
}

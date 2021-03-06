use rand::thread_rng;
use rand_core::{CryptoRng, RngCore};
use rsa::{hash::Hash, BigUint, PaddingScheme, PublicKey, RSAPrivateKey, RSAPublicKey};
use sha2::{Digest, Sha256, Sha384, Sha512};
use thiserror::Error;

use std::borrow::Cow;

use crate::{Algorithm, AlgorithmSignature};

/// Errors that may occur during token parsing.
#[derive(Debug, Error)]
pub enum RsaError {
    #[error("Unsupported signature length")]
    UnsupportedSignatureLength,
    #[error("Unsupported modulus size")]
    UnsupportedModulusSize,
    #[error("Invalid key: {0}")]
    InvalidKey(rsa::errors::Error),
    #[error("Key generation error: {0}")]
    KeygenError(rsa::errors::Error),
}

#[derive(Debug)]
pub struct Signature(Vec<u8>);

impl AlgorithmSignature for Signature {
    fn try_from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        match bytes.len() {
            256 | 384 | 512 => Ok(Signature(bytes.to_vec())),
            _ => Err(RsaError::UnsupportedSignatureLength.into()),
        }
    }

    fn as_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.0.clone())
    }
}

/// RSA padding algorithm.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Padding {
    /// PKCS1v1.5
    Pkcs1v15,
    /// PSS
    Pss,
}

/// An RSA public key.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RsaVerifyingKey(RSAPublicKey);

impl AsRef<RSAPublicKey> for RsaVerifyingKey {
    fn as_ref(&self) -> &RSAPublicKey {
        &self.0
    }
}

impl RsaVerifyingKey {
    /// Create a verification key from a DER-encoded set of the parameters.
    pub fn from_der(der: &[u8]) -> anyhow::Result<RsaVerifyingKey> {
        match RSAPublicKey::from_pkcs8(&der) {
            Err(e) => Err(RsaError::InvalidKey(e).into()),
            Ok(key) => Ok(RsaVerifyingKey(key)),
        }
    }

    /// Create a verification key from a modulus and a public exponent.
    pub fn from_components(n: &[u8], e: &[u8]) -> anyhow::Result<RsaVerifyingKey> {
        let n = BigUint::from_bytes_be(n);
        let e = BigUint::from_bytes_be(e);
        match RSAPublicKey::new(n, e) {
            Err(e) => Err(RsaError::InvalidKey(e).into()),
            Ok(key) => Ok(RsaVerifyingKey(key)),
        }
    }
}

/// An RSA signing key.
#[derive(Debug)]
pub struct RsaSigningKey(RSAPrivateKey);

impl AsRef<RSAPrivateKey> for RsaSigningKey {
    fn as_ref(&self) -> &RSAPrivateKey {
        &self.0
    }
}

impl RsaSigningKey {
    /// Create a signing key from a DER-encoded set of the parameters.
    pub fn from_der(der: &[u8]) -> anyhow::Result<RsaSigningKey> {
        match RSAPrivateKey::from_pkcs8(&der) {
            Err(e) => Err(RsaError::InvalidKey(e).into()),
            Ok(key) => {
                key.validate().map_err(RsaError::InvalidKey)?;
                Ok(RsaSigningKey(key))
            }
        }
    }

    /// Convert a signing key to a verification key.
    pub fn to_verifying_key(&self) -> RsaVerifyingKey {
        RsaVerifyingKey(RSAPublicKey::from(&self.0))
    }
}

/// Integrity algorithm using digital signatures on RSA-PKCS1v1.5 and SHA-256.
///
/// The name of the algorithm is specified as `RS256` as per the [IANA registry].
///
/// *This type is available if the crate is built with the `rsa` feature.*
///
/// [IANA registry]: https://www.iana.org/assignments/jose/jose.xhtml
#[derive(Debug)]
pub struct Rsa {
    hash_alg: Hash,
    padding_alg: Padding,
}

impl Rsa {
    /// Create an instance using a specific hash function and padding
    pub fn new(hash_alg: Hash, padding_alg: Padding) -> Self {
        Rsa {
            hash_alg,
            padding_alg,
        }
    }
}

pub trait RsaVariant {
    fn rsa() -> Rsa;
}

impl<T: RsaVariant> Algorithm for T {
    type SigningKey = RsaSigningKey;
    type VerifyingKey = RsaVerifyingKey;
    type Signature = Signature;

    fn name(&self) -> Cow<'static, str> {
        Self::rsa().name()
    }

    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        Self::rsa().sign(signing_key, message)
    }

    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool {
        Self::rsa().verify_signature(signature, verifying_key, message)
    }
}

impl Rsa {
    fn hash(&self, message: &[u8]) -> Vec<u8> {
        match self.hash_alg {
            Hash::SHA2_256 => Sha256::digest(message).to_vec(),
            Hash::SHA2_384 => Sha384::digest(message).to_vec(),
            Hash::SHA2_512 => Sha512::digest(message).to_vec(),
            _ => unreachable!(),
        }
    }

    fn padding_scheme(&self) -> PaddingScheme {
        match self.padding_alg {
            Padding::Pkcs1v15 => PaddingScheme::new_pkcs1v15_sign(Some(self.hash_alg)),
            Padding::Pss => {
                let rng = rand_core::OsRng {};
                match self.hash_alg {
                    Hash::SHA2_256 => PaddingScheme::new_pss::<Sha256, _>(rng),
                    Hash::SHA2_384 => PaddingScheme::new_pss::<Sha384, _>(rng),
                    Hash::SHA2_512 => PaddingScheme::new_pss::<Sha512, _>(rng),
                    _ => unreachable!(),
                }
            }
        }
    }

    fn name(&self) -> Cow<'static, str> {
        let name = match self.hash_alg {
            Hash::SHA2_256 => "RS256",
            Hash::SHA2_384 => "RS384",
            Hash::SHA2_512 => "RS512",
            _ => unreachable!(),
        };
        Cow::Borrowed(name)
    }

    fn sign(&self, signing_key: &RsaSigningKey, message: &[u8]) -> Signature {
        let digest = self.hash(message);
        let mut rng = thread_rng();
        Signature(
            signing_key
                .as_ref()
                .sign_blinded(&mut rng, self.padding_scheme(), &digest)
                .expect("Unexpected RSA signature failure"),
        )
    }

    fn verify_signature(
        &self,
        signature: &Signature,
        verifying_key: &RsaVerifyingKey,
        message: &[u8],
    ) -> bool {
        let digest = self.hash(message);
        verifying_key
            .as_ref()
            .verify(self.padding_scheme(), &digest, &signature.0)
            .is_ok()
    }

    /// Generate a new key pair.
    pub fn generate<R: CryptoRng + RngCore>(
        rng: &mut R,
        modulus_bits: usize,
    ) -> anyhow::Result<(RsaSigningKey, RsaVerifyingKey)> {
        match modulus_bits {
            2048 | 3072 | 4096 => {}
            _ => return Err(RsaError::UnsupportedModulusSize.into()),
        }
        let signing_key = match RSAPrivateKey::new(rng, modulus_bits) {
            Err(e) => return Err(RsaError::KeygenError(e).into()),
            Ok(key) => RsaSigningKey(key),
        };
        let verifying_key = signing_key.to_verifying_key();
        Ok((signing_key, verifying_key))
    }
}

/// RSA-PKCS1v1.5 with SHA-256 as a hash function
#[derive(Debug)]
pub struct Rs256;

impl RsaVariant for Rs256 {
    fn rsa() -> Rsa {
        Rsa::new(Hash::SHA2_256, Padding::Pkcs1v15)
    }
}

/// RSA-PKCS1v1.5 with SHA-384 as a hash function
#[derive(Debug)]
pub struct Rs384;

impl RsaVariant for Rs384 {
    fn rsa() -> Rsa {
        Rsa::new(Hash::SHA2_384, Padding::Pkcs1v15)
    }
}

/// RSA-PKCS1v1.5 with SHA-512 as a hash function
#[derive(Debug)]
pub struct Rs512;

impl RsaVariant for Rs512 {
    fn rsa() -> Rsa {
        Rsa::new(Hash::SHA2_512, Padding::Pkcs1v15)
    }
}

/// RSASSA-PSS with SHA-256 as a hash function
#[derive(Debug)]
pub struct Ps256;

impl RsaVariant for Ps256 {
    fn rsa() -> Rsa {
        Rsa::new(Hash::SHA2_256, Padding::Pss)
    }
}

/// RSASSA-PSS with SHA-384 as a hash function
#[derive(Debug)]
pub struct Ps384;

impl RsaVariant for Ps384 {
    fn rsa() -> Rsa {
        Rsa::new(Hash::SHA2_384, Padding::Pss)
    }
}

/// RSASSA-PSS with SHA-512 as a hash function
#[derive(Debug)]
pub struct Ps512;

impl RsaVariant for Ps512 {
    fn rsa() -> Rsa {
        Rsa::new(Hash::SHA2_512, Padding::Pss)
    }
}

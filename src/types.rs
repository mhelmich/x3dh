use crate::errors::X3dhError;
use arrayref::array_ref;
use base64;
use core::convert::TryFrom;
use rand::{thread_rng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek;

// implemented after:
// https://signal.org/docs/specifications/x3dh/#x3dh-parameterss

// byte size of a Curve25519 private key
pub(crate) const CURVE25519_SECRET_LENGTH: usize = 32;
// byte size of a Curve25519 public key
pub(crate) const CURVE25519_PUBLIC_LENGTH: usize = CURVE25519_SECRET_LENGTH;
// byte size of a diffie hellman shared secret
pub(crate) const SHARED_SECRET_LENGTH: usize = 32;
// byte size of a Curve25519 signature
pub(crate) const SIGNATURE_LENGTH: usize = 64;
// byte size of a sha256 hash
pub(crate) const HASH_LENGTH: usize = 32;
// byte size of an aes256 key
pub(crate) const AES256_SECRET_LENGTH: usize = 32;

// Alice then sends Bob an initial message containing:
//     Alice's identity key IKA
//     Alice's ephemeral key EKA
//     Identifiers stating which of Bob's prekeys Alice used
//     An initial ciphertext encrypted with some AEAD encryption scheme [4] using AD as associated data and using an encryption key which is either SK or the output from some cryptographic PRF keyed by SK.
pub(crate) struct InitialMessage {
    pub(crate) identity_key: PublicKey,
    pub(crate) ephemeral_key: PublicKey,
    pub(crate) prekey_hash: Sha256Hash,
    pub(crate) one_time_key_hash: Sha256Hash,
}

impl InitialMessage {
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out
    }

    fn to_base64(&self) -> String {
        base64::encode(self.to_bytes())
    }
}

impl TryFrom<String> for InitialMessage {
    type Error = X3dhError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let bytes = base64::decode(value)?;

        let identity_key = PublicKey(*array_ref![bytes, 0, CURVE25519_PUBLIC_LENGTH]);
        let ephemeral_key = PublicKey(*array_ref![
            bytes,
            CURVE25519_PUBLIC_LENGTH,
            CURVE25519_PUBLIC_LENGTH
        ]);
        let prekey_hash = Sha256Hash(*array_ref![
            bytes,
            2 * CURVE25519_PUBLIC_LENGTH,
            HASH_LENGTH
        ]);
        let one_time_key_hash = Sha256Hash(*array_ref![
            bytes,
            2 * CURVE25519_PUBLIC_LENGTH + HASH_LENGTH,
            HASH_LENGTH
        ]);

        Ok(Self {
            identity_key,
            ephemeral_key,
            prekey_hash,
            one_time_key_hash,
        })
    }
}

// To perform an X3DH key agreement with Bob, Alice contacts the server and fetches a "prekey bundle" containing the following values:
//     Bob's identity key IKB
//     Bob's signed prekey SPKB
//     Bob's prekey signature Sig(IKB, Encode(SPKB))
//     (Optionally) Bob's one-time prekey OPKB
pub(crate) struct PrekeyBundle {
    pub(crate) identity_key: PublicKey,
    pub(crate) signed_prekey: PublicKey,
    pub(crate) prekey_signature: Signature,
    pub(crate) one_time_prekey: PublicKey,
}

impl PrekeyBundle {
    // the byte size of a prekey bundle
    pub(crate) const SIZE: usize = CURVE25519_SECRET_LENGTH
        + CURVE25519_SECRET_LENGTH
        + SIGNATURE_LENGTH
        + CURVE25519_SECRET_LENGTH;

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.identity_key.0.as_ref());
        out.extend_from_slice(self.signed_prekey.0.as_ref());
        out.extend_from_slice(self.prekey_signature.0.as_ref());
        out.extend_from_slice(self.one_time_prekey.0.as_ref());
        out
    }

    pub(crate) fn to_base64(&self) -> String {
        base64::encode(self.to_bytes())
    }
}

impl TryFrom<String> for PrekeyBundle {
    type Error = X3dhError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let bytes = base64::decode(value)?;
        if bytes.len() != Self::SIZE {
            return Err(String::from("invalid prekey bundle").into());
        }

        let identity_key = PublicKey(*array_ref![bytes, 0, CURVE25519_PUBLIC_LENGTH]);
        let signed_prekey = PublicKey(*array_ref![
            bytes,
            CURVE25519_PUBLIC_LENGTH,
            CURVE25519_PUBLIC_LENGTH
        ]);
        let prekey_signature = Signature(*array_ref![
            bytes,
            2 * CURVE25519_PUBLIC_LENGTH,
            SIGNATURE_LENGTH
        ]);
        let one_time_prekey = PublicKey(*array_ref![
            bytes,
            2 * CURVE25519_PUBLIC_LENGTH + SIGNATURE_LENGTH,
            CURVE25519_PUBLIC_LENGTH
        ]);

        Ok(Self {
            identity_key,
            signed_prekey,
            prekey_signature,
            one_time_prekey,
        })
    }
}

pub(crate) struct Sha256Hash([u8; HASH_LENGTH]);

impl From<&[u8; HASH_LENGTH]> for Sha256Hash {
    fn from(value: &[u8; HASH_LENGTH]) -> Sha256Hash {
        Sha256Hash(*value)
    }
}

pub(crate) struct PrivateKey([u8; CURVE25519_SECRET_LENGTH]);

impl PrivateKey {
    pub(crate) fn new() -> PrivateKey {
        let rng = thread_rng();
        let key = x25519_dalek::StaticSecret::new(rng);
        PrivateKey(key.to_bytes())
    }

    pub(crate) fn diffie_hellman(&self, public_key: &PublicKey) -> SharedSecret {
        let dalek_private_key = x25519_dalek::StaticSecret::from(self.0);
        let dalek_public_key = x25519_dalek::PublicKey::from(public_key.0);
        let dh = dalek_private_key.diffie_hellman(&dalek_public_key);
        SharedSecret(dh.to_bytes())
    }
}

impl AsRef<[u8; CURVE25519_SECRET_LENGTH]> for PrivateKey {
    fn as_ref(&self) -> &[u8; CURVE25519_SECRET_LENGTH] {
        &self.0
    }
}

pub(crate) struct PublicKey([u8; CURVE25519_PUBLIC_LENGTH]);

impl From<PrivateKey> for PublicKey {
    fn from(private_key: PrivateKey) -> PublicKey {
        let dalek_private_key = x25519_dalek::StaticSecret::from(private_key.0);
        let dalek_public_key = x25519_dalek::PublicKey::from(&dalek_private_key);
        PublicKey(dalek_public_key.to_bytes())
    }
}

impl From<&PrivateKey> for PublicKey {
    fn from(private_key: &PrivateKey) -> PublicKey {
        let dalek_private_key = x25519_dalek::StaticSecret::from(private_key.0);
        let dalek_public_key = x25519_dalek::PublicKey::from(&dalek_private_key);
        PublicKey(dalek_public_key.to_bytes())
    }
}

impl AsRef<[u8; CURVE25519_PUBLIC_LENGTH]> for PublicKey {
    fn as_ref(&self) -> &[u8; CURVE25519_PUBLIC_LENGTH] {
        &self.0
    }
}

impl PublicKey {
    pub(crate) fn hash(&self) -> Sha256Hash {
        let digest = Sha256::digest(self.0.as_ref());
        Sha256Hash(*array_ref![digest, 0, HASH_LENGTH])
    }

    pub(crate) fn diffie_hellman(&self, public_key: &PublicKey) -> SharedSecret {
        let dalek_private_key = x25519_dalek::StaticSecret::from(self.0);
        let dalek_public_key = x25519_dalek::PublicKey::from(public_key.0);
        let dh = dalek_private_key.diffie_hellman(&dalek_public_key);
        SharedSecret(dh.to_bytes())
    }
}

pub(crate) struct Signature([u8; SIGNATURE_LENGTH]);

impl AsRef<[u8; SIGNATURE_LENGTH]> for Signature {
    fn as_ref(&self) -> &[u8; SIGNATURE_LENGTH] {
        &self.0
    }
}

impl From<[u8; SIGNATURE_LENGTH]> for Signature {
    fn from(value: [u8; SIGNATURE_LENGTH]) -> Signature {
        Signature(value)
    }
}

pub(crate) struct EncryptionKey([u8; SHARED_SECRET_LENGTH]);

impl From<[u8; SHARED_SECRET_LENGTH]> for EncryptionKey {
    fn from(value: [u8; SHARED_SECRET_LENGTH]) -> EncryptionKey {
        EncryptionKey(value)
    }
}

pub(crate) struct DecryptionKey([u8; SHARED_SECRET_LENGTH]);

impl From<[u8; SHARED_SECRET_LENGTH]> for DecryptionKey {
    fn from(value: [u8; SHARED_SECRET_LENGTH]) -> DecryptionKey {
        DecryptionKey(value)
    }
}

pub(crate) struct SharedSecret([u8; SHARED_SECRET_LENGTH]);

impl AsRef<[u8; SHARED_SECRET_LENGTH]> for SharedSecret {
    fn as_ref(&self) -> &[u8; SHARED_SECRET_LENGTH] {
        &self.0
    }
}

#[test]
fn test_serde_prekey_bundle() {
    let mut rng = thread_rng();
    let mut signature_bytes = [0u8; 64];
    rng.fill_bytes(&mut signature_bytes);
    let signature = Signature(signature_bytes);

    let key1 = PublicKey::from(PrivateKey::new());
    let key2 = PublicKey::from(PrivateKey::new());
    let key3 = PublicKey::from(PrivateKey::new());

    let pb1 = PrekeyBundle {
        identity_key: key1,
        signed_prekey: key2,
        prekey_signature: signature,
        one_time_prekey: key3,
    };

    let b64 = pb1.to_base64();
    let pb2 = PrekeyBundle::try_from(b64).unwrap();
    assert_eq!(pb1.identity_key.0, pb2.identity_key.0);
    assert_eq!(pb1.signed_prekey.0, pb2.signed_prekey.0);
    assert_eq!(pb1.prekey_signature.0, pb2.prekey_signature.0);
    assert_eq!(pb1.one_time_prekey.0, pb2.one_time_prekey.0);
}

#[test]
fn test_hash_public_key() {
    let key1 = PublicKey::from(PrivateKey::new());
    let key2 = PublicKey::from(PrivateKey::new());
    assert_ne!(key1.hash().0, key2.hash().0);
}

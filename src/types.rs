use crate::errors::X3dhError;
use arrayref::array_ref;
use base64;
use core::convert::TryFrom;
use rand::{thread_rng, RngCore};
use x25519_dalek;

// implemented after:
// https://signal.org/docs/specifications/x3dh/#x3dh-parameterss

// byte size of a Curve25519 private key
pub(crate) const CURVE25519_SECRET_LENGTH: usize = 32;
// byte size of a Curve25519 public key
pub(crate) const CURVE25519_PUBLIC_LENGTH: usize = CURVE25519_SECRET_LENGTH;
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
pub(crate) struct InitialMessage {}

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
    const SIZE: usize = CURVE25519_SECRET_LENGTH
        + CURVE25519_SECRET_LENGTH
        + SIGNATURE_LENGTH
        + CURVE25519_SECRET_LENGTH;

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.identity_key.0.as_ref());
        out.extend_from_slice(self.signed_prekey.0.as_ref());
        out.extend_from_slice(self.prekey_signature.0.as_ref());
        out.extend_from_slice(self.one_time_prekey.0.as_ref());
        out
    }

    fn to_base64(&self) -> String {
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

pub(crate) struct EncryptionKey([u8; AES256_SECRET_LENGTH]);

pub(crate) struct PrivateKey([u8; CURVE25519_SECRET_LENGTH]);

impl PrivateKey {
    fn new() -> PrivateKey {
        let rng = thread_rng();
        let key = x25519_dalek::StaticSecret::new(rng);
        PrivateKey(key.to_bytes())
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

pub(crate) struct Signature([u8; SIGNATURE_LENGTH]);

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

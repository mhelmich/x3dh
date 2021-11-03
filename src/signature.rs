use crate::types::{PrivateKey, PublicKey, Signature};
use crate::types::{CURVE25519_SECRET_LENGTH, SIGNATURE_LENGTH};
use crate::xeddsa::{XEddsaSigner, XEddsaVerifier};
use arrayref::array_ref;
use rand::{thread_rng, RngCore};

pub(crate) fn sign(key: &PrivateKey, data: &[u8]) -> Signature {
    let mut rng = thread_rng();
    let mut nonce = [0u8; SIGNATURE_LENGTH];
    rng.fill_bytes(&mut nonce);
    let k =
        x25519_dalek::StaticSecret::from(*array_ref!(key.as_ref(), 0, CURVE25519_SECRET_LENGTH));
    Signature::from(k.sign(data, &nonce))
}

pub(crate) fn verify(signature: &Signature, key: &PublicKey, data: &[u8]) -> bool {
    let dalek_public_key = x25519_dalek::PublicKey::from(*key.as_ref());
    dalek_public_key.verify(data, signature.as_ref())
}

#[test]
fn test_sign_verify() {
    let private_key = PrivateKey::new();
    let public_key = PublicKey::from(&private_key);
    let data = String::from("Hello World!!!");

    let sig = sign(&private_key, data.as_bytes());
    assert!(verify(&sig, &public_key, data.as_bytes()));
}

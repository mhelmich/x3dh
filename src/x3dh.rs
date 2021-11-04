use crate::errors::X3dhError;
use crate::signature::{sign, verify};
use crate::types::{
    AssociatedData, InitialMessage, PrekeyBundle, PrivateKey, PublicKey, SharedSecret,
};
use crate::types::{AES256_SECRET_LENGTH, CURVE25519_PUBLIC_LENGTH, HASH_LENGTH};
use arrayref::array_ref;
use hkdf::Hkdf;
use rand::{thread_rng, RngCore};
use sha2::Sha256;
use std::convert::TryFrom;

pub(crate) fn generate_prekey_bundle(
    identity_key: &PrivateKey,
    prekey: &PrivateKey,
) -> PrekeyBundle {
    let prekey_pub = PublicKey::from(prekey);
    let signature = sign(&identity_key, prekey_pub.as_ref());
    let one_time_key = PrivateKey::new();
    PrekeyBundle {
        identity_key: PublicKey::from(identity_key),
        signed_prekey: prekey_pub,
        prekey_signature: signature,
        one_time_prekey: PublicKey::from(one_time_key),
    }
}

pub(crate) fn process_prekey_bundle(
    identity_key: PrivateKey,
    bundle: PrekeyBundle,
) -> Result<(InitialMessage, SharedSecret), X3dhError> {
    let verified = verify(
        &bundle.prekey_signature,
        &bundle.identity_key,
        bundle.signed_prekey.as_ref(),
    );
    if !verified {
        return Err(X3dhError::from("invalid prekey bundle"));
    }

    let identity_key_pub = PublicKey::from(&identity_key);
    let ephemeral_key = PrivateKey::new();
    let ephemeral_key_pub = PublicKey::from(ephemeral_key);

    let dh1 = identity_key_pub.diffie_hellman(&bundle.signed_prekey);
    let dh2 = ephemeral_key_pub.diffie_hellman(&bundle.identity_key);
    let dh3 = ephemeral_key_pub.diffie_hellman(&bundle.signed_prekey);
    let dh4 = ephemeral_key_pub.diffie_hellman(&bundle.one_time_prekey);

    let shared_key = hkdf(String::from("x3dh"), dh1, dh2, dh3, dh4)?;

    let associated_data = AssociatedData {
        initiator_identity_key: PublicKey::from(&identity_key),
        responder_identity_key: bundle.identity_key,
    };

    Ok((
        InitialMessage {
            identity_key: PublicKey::from(identity_key),
            ephemeral_key: ephemeral_key_pub,
            prekey_hash: bundle.signed_prekey.hash(),
            one_time_key_hash: bundle.one_time_prekey.hash(),
            associated_data,
        },
        shared_key,
    ))
}

fn hkdf(
    info: String,
    dh1: SharedSecret,
    dh2: SharedSecret,
    dh3: SharedSecret,
    dh4: SharedSecret,
) -> Result<SharedSecret, X3dhError> {
    // HKDF input key material = F || KM, where KM is an input byte sequence containing secret key material, and F is a byte sequence containing 32 0xFF bytes if curve is X25519, and 57 0xFF bytes if curve is X448. F is used for cryptographic domain separation with XEdDSA [2].
    let mut dhs = Vec::new();
    dhs.extend_from_slice(&[0xFFu8; 32]);
    dhs.extend_from_slice(dh1.as_ref());
    dhs.extend_from_slice(dh2.as_ref());
    dhs.extend_from_slice(dh3.as_ref());
    dhs.extend_from_slice(dh4.as_ref());

    // HKDF salt = A zero-filled byte sequence with length equal to the hash output length.
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), dhs.as_ref());
    let mut okm = [0u8; AES256_SECRET_LENGTH];
    // HKDF info = The info parameter from Section 2.1.
    hk.expand(info.as_bytes(), &mut okm)?;

    let shared_key = SharedSecret::from(*array_ref!(okm, 0, AES256_SECRET_LENGTH));
    Ok(shared_key)
}

pub(crate) fn process_initial_message(
    identity_key: PublicKey,
    signed_prekey: PublicKey,
    one_time_prekey: PublicKey,
    msg: InitialMessage,
) -> Result<SharedSecret, X3dhError> {
    let dh1 = msg.identity_key.diffie_hellman(&signed_prekey);
    let dh2 = msg.ephemeral_key.diffie_hellman(&identity_key);
    let dh3 = msg.ephemeral_key.diffie_hellman(&signed_prekey);
    let dh4 = msg.ephemeral_key.diffie_hellman(&one_time_prekey);

    let shared_key = hkdf(String::from("x3dh"), dh1, dh2, dh3, dh4)?;
    Ok(shared_key)
}

#[test]
fn test_generate_prekey_bundle() {
    let identity_key = PrivateKey::new();
    let prekey = PrivateKey::new();
    let pb1 = generate_prekey_bundle(&identity_key, &prekey);
    let pb1_bytes = pb1.to_bytes();
    assert_eq!(pb1_bytes.len(), PrekeyBundle::SIZE);

    let pb1_base64 = pb1.to_base64();
    let pb2 = PrekeyBundle::try_from(pb1_base64).unwrap();
    assert_eq!(pb2.one_time_prekey.as_ref(), pb1.one_time_prekey.as_ref());
}

#[test]
fn test_process_prekey_bundle() {
    let identity_key = PrivateKey::new();
    let identity_key_pub = PublicKey::from(&identity_key);
    let prekey = PrivateKey::new();
    let pb = generate_prekey_bundle(&identity_key, &prekey);

    let (initial_message, shared_key) = process_prekey_bundle(identity_key, pb).unwrap();
    assert_eq!(
        initial_message.identity_key.as_ref(),
        identity_key_pub.as_ref()
    );

    let im_bytes = initial_message.to_bytes();
    assert_eq!(
        im_bytes.len(),
        4 * CURVE25519_PUBLIC_LENGTH + 2 * HASH_LENGTH
    );

    let mut rng = thread_rng();
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);

    let data = b"Hello World!";
    let aad = b"Extra auth data";
    let cipher_text = shared_key.encrypt(data, &nonce, aad).unwrap();
    let clear_text = shared_key
        .decrypt(cipher_text.as_ref(), &nonce, aad)
        .unwrap();
    assert_eq!(data.to_vec(), clear_text);
}

#[test]
fn test_process_initial_message() {
    let identity_key = PrivateKey::new();
    let prekey = PrivateKey::new();
    let pb = generate_prekey_bundle(&identity_key, &prekey);

    let (initial_message, shared_key1) = process_prekey_bundle(identity_key, pb).unwrap();
    let shared_key2 = process_initial_message(
        pb.identity_key,
        pb.signed_prekey,
        pb.one_time_prekey,
        initial_message,
    )
    .unwrap();
    assert_eq!(shared_key1.as_ref(), shared_key2.as_ref());
    let data = b"Hello World!";
    let nonce = b"12byte_nonce";
    let cipher_text = shared_key1
        .encrypt(data, nonce, &initial_message.associated_data.to_bytes())
        .unwrap();
    let clear_text = shared_key2
        .decrypt(
            &cipher_text,
            nonce,
            &initial_message.associated_data.to_bytes(),
        )
        .unwrap();
    assert_eq!(data.to_vec(), clear_text);
}

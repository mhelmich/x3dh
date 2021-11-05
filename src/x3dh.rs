use crate::errors::X3dhError;
use crate::signature::{sign, verify};
use crate::types::{
    AssociatedData, DecryptionKey, EncryptionKey, InitialMessage, PrekeyBundle, PrivateKey,
    PublicKey, SharedSecret, AES256_SECRET_LENGTH,
};
use arrayref::array_ref;
use hkdf::Hkdf;
use sha2::Sha256;

pub(crate) fn generate_prekey_bundle(
    identity_key: &PrivateKey,
    prekey: PublicKey,
    one_time_key: PublicKey,
) -> PrekeyBundle {
    let signature = sign(identity_key, prekey.as_ref());
    PrekeyBundle {
        identity_key: PublicKey::from(identity_key),
        signed_prekey: prekey,
        prekey_signature: signature,
        one_time_prekey: one_time_key,
    }
}

pub(crate) fn process_prekey_bundle(
    identity_key: PrivateKey,
    bundle: PrekeyBundle,
) -> Result<(InitialMessage, EncryptionKey, DecryptionKey), X3dhError> {
    let verified = verify(
        &bundle.prekey_signature,
        &bundle.identity_key,
        bundle.signed_prekey.as_ref(),
    );
    if !verified {
        return Err(X3dhError::from("invalid prekey bundle"));
    }

    let ephemeral_key = PrivateKey::new();
    let ephemeral_key_pub = PublicKey::from(&ephemeral_key);

    // DH1 = DH(IKA, SPKB)
    let dh1 = identity_key.diffie_hellman(&bundle.signed_prekey);
    // DH2 = DH(EKA, IKB)
    let dh2 = ephemeral_key.diffie_hellman(&bundle.identity_key);
    // DH3 = DH(EKA, SPKB)
    let dh3 = ephemeral_key.diffie_hellman(&bundle.signed_prekey);
    // DH4 = DH(EKA, OPKB)
    let dh4 = ephemeral_key.diffie_hellman(&bundle.one_time_prekey);

    let (shared_key1, shared_key2) = hkdf(String::from("x3dh"), dh1, dh2, dh3, dh4)?;

    // AD = Encode(IKA) || Encode(IKB)
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
        EncryptionKey::from(shared_key1),
        DecryptionKey::from(shared_key2),
    ))
}

pub(crate) fn process_initial_message(
    identity_key: PrivateKey,
    signed_prekey: PrivateKey,
    one_time_prekey: PrivateKey,
    msg: InitialMessage,
) -> Result<(EncryptionKey, DecryptionKey), X3dhError> {
    // DH1 = DH(SPKB, IKA)
    let dh1 = signed_prekey.diffie_hellman(&msg.identity_key);
    // DH2 = DH(IKB, EKA)
    let dh2 = identity_key.diffie_hellman(&msg.ephemeral_key);
    // DH3 = DH(SPKB, EKA)
    let dh3 = signed_prekey.diffie_hellman(&msg.ephemeral_key);
    // DH4 = DH(OPKB, EKA)
    let dh4 = one_time_prekey.diffie_hellman(&msg.ephemeral_key);

    let (shared_key1, shared_key2) = hkdf(String::from("x3dh"), dh1, dh2, dh3, dh4)?;
    Ok((
        EncryptionKey::from(shared_key2),
        DecryptionKey::from(shared_key1),
    ))
}

fn hkdf(
    info: String,
    dh1: SharedSecret,
    dh2: SharedSecret,
    dh3: SharedSecret,
    dh4: SharedSecret,
) -> Result<(SharedSecret, SharedSecret), X3dhError> {
    // HKDF input key material = F || KM, where KM is an input byte sequence containing secret key material, and F is a byte sequence containing 32 0xFF bytes if curve is X25519, and 57 0xFF bytes if curve is X448. F is used for cryptographic domain separation with XEdDSA [2].
    let mut dhs = vec![0xFFu8; 32];
    dhs.extend_from_slice(dh1.as_ref());
    dhs.extend_from_slice(dh2.as_ref());
    dhs.extend_from_slice(dh3.as_ref());
    dhs.extend_from_slice(dh4.as_ref());

    // HKDF salt = A zero-filled byte sequence with length equal to the hash output length.
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), dhs.as_ref());
    let mut okm = [0u8; 2 * AES256_SECRET_LENGTH];
    // HKDF info = The info parameter from Section 2.1.
    hk.expand(info.as_bytes(), &mut okm)?;

    let shared_key1 = SharedSecret::from(*array_ref!(okm, 0, AES256_SECRET_LENGTH));
    let shared_key2 =
        SharedSecret::from(*array_ref!(okm, AES256_SECRET_LENGTH, AES256_SECRET_LENGTH));
    Ok((shared_key1, shared_key2))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CURVE25519_PUBLIC_LENGTH, SHA256_HASH_LENGTH};
    use std::convert::TryFrom;

    #[test]
    fn test_generate_prekey_bundle() {
        let identity_key = PrivateKey::new();
        let prekey = PrivateKey::new();
        let prekey_pub = PublicKey::from(prekey);
        let one_time_key = PrivateKey::new();
        let one_time_key_pub = PublicKey::from(one_time_key);
        let pb1 = generate_prekey_bundle(&identity_key, prekey_pub, one_time_key_pub);
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
        let prekey_pub = PublicKey::from(prekey);
        let one_time_key = PrivateKey::new();
        let one_time_key_pub = PublicKey::from(one_time_key);
        let pb = generate_prekey_bundle(&identity_key, prekey_pub, one_time_key_pub);

        let (initial_message, encryption_key, decryption_key) =
            process_prekey_bundle(identity_key, pb).unwrap();
        assert_eq!(
            initial_message.identity_key.as_ref(),
            identity_key_pub.as_ref()
        );
        assert_eq!(encryption_key.as_ref().len(), AES256_SECRET_LENGTH);
        assert_eq!(decryption_key.as_ref().len(), AES256_SECRET_LENGTH);

        let im_bytes = initial_message.to_bytes();
        assert_eq!(
            im_bytes.len(),
            4 * CURVE25519_PUBLIC_LENGTH + 2 * SHA256_HASH_LENGTH
        );
    }

    #[test]
    fn test_process_initial_message() {
        let identity_key = PrivateKey::new();
        let prekey = PrivateKey::new();
        let prekey_pub = PublicKey::from(&prekey);
        let one_time_key = PrivateKey::new();
        let one_time_key_pub = PublicKey::from(&one_time_key);
        let pb = generate_prekey_bundle(&identity_key, prekey_pub, one_time_key_pub);

        let (initial_message, encryption_key1, decryption_key1) =
            process_prekey_bundle(identity_key.clone(), pb).unwrap();
        let (encryption_key2, decryption_key2) =
            process_initial_message(identity_key, prekey, one_time_key, initial_message).unwrap();
        assert_eq!(encryption_key1.as_ref(), decryption_key2.as_ref());
        assert_eq!(decryption_key1.as_ref(), encryption_key2.as_ref());
        let data = b"Hello World!";
        let nonce = b"12byte_nonce";
        let aad = initial_message.associated_data;
        let cipher_text = encryption_key1.encrypt(data, nonce, &aad).unwrap();
        let clear_text = decryption_key2.decrypt(&cipher_text, nonce, &aad).unwrap();
        assert_eq!(data.to_vec(), clear_text);
    }
}

use crate::errors::X3dhError;
use crate::types::{
    AssociatedData, DecryptionKey, EncryptionKey, InitialMessage, PrekeyBundle, PrivateKey,
    PublicKey, Sha256Hash, AES256_NONCE_LENGTH,
};
use crate::x3dh;
use arrayref::array_ref;
use rand::{thread_rng, RngCore};
use std::collections::HashMap;

pub struct KeyVault {
    identity_key: PrivateKey,
    prekey_pub: PublicKey,
    prekeys: HashMap<Sha256Hash, PrivateKey>,
    one_time_keys: HashMap<Sha256Hash, PrivateKey>,
    encryption_keys: HashMap<Sha256Hash, EncryptionKey>,
    decryption_keys: HashMap<Sha256Hash, DecryptionKey>,
    associated_data: HashMap<Sha256Hash, AssociatedData>,
}

impl KeyVault {
    pub fn new() -> Self {
        let mut prekeys = HashMap::new();
        let prekey = PrivateKey::new();
        let prekey_pub = PublicKey::from(&prekey);
        prekeys.insert(prekey_pub.hash(), prekey);
        Self {
            identity_key: PrivateKey::new(),
            prekey_pub,
            prekeys,
            one_time_keys: HashMap::new(),
            encryption_keys: HashMap::new(),
            decryption_keys: HashMap::new(),
            associated_data: HashMap::new(),
        }
    }

    pub fn new_prekey_bundle(&mut self) -> PrekeyBundle {
        let otk_pub = self.new_one_time_key();
        x3dh::generate_prekey_bundle(&self.identity_key, self.prekey_pub, otk_pub)
    }

    pub fn process_prekey_bundle(
        &mut self,
        bundle: PrekeyBundle,
    ) -> Result<(Sha256Hash, InitialMessage), X3dhError> {
        let (initial_message, encryption_key, decryption_key) =
            x3dh::process_prekey_bundle(self.identity_key.clone(), bundle)?;
        let recipient_handle = bundle.identity_key.hash();
        self.encryption_keys
            .insert(recipient_handle, encryption_key);
        self.decryption_keys
            .insert(recipient_handle, decryption_key);
        self.associated_data
            .insert(recipient_handle, initial_message.associated_data);
        Ok((recipient_handle, initial_message))
    }

    pub fn process_initial_message(
        &mut self,
        initial_message: InitialMessage,
    ) -> Result<Sha256Hash, X3dhError> {
        let used_prekey = self
            .prekeys
            .get(&initial_message.prekey_hash)
            .ok_or_else(|| X3dhError::from("could not find prekey"))?;
        let used_one_time_key = self
            .one_time_keys
            .get(&initial_message.one_time_key_hash)
            .ok_or_else(|| X3dhError::from("could not find one time key"))?;
        let (encryption_key, decryption_key) = x3dh::process_initial_message(
            self.identity_key.clone(),
            used_prekey.clone(),
            used_one_time_key.clone(),
            initial_message,
        )?;
        let recipient_handle = initial_message.identity_key.hash();
        self.encryption_keys
            .insert(recipient_handle, encryption_key);
        self.decryption_keys
            .insert(recipient_handle, decryption_key);
        self.associated_data
            .insert(recipient_handle, initial_message.associated_data);
        Ok(recipient_handle)
    }

    pub fn encrypt_msg(
        &self,
        recipient_handle: Sha256Hash,
        msg: Vec<u8>,
    ) -> Result<Vec<u8>, X3dhError> {
        let cipher = self
            .encryption_keys
            .get(&recipient_handle)
            .ok_or_else(|| X3dhError::from("could not find encryption key"))?;
        let aad = self
            .associated_data
            .get(&recipient_handle)
            .ok_or_else(|| X3dhError::from("could not find associated data"))?;

        let mut rng = thread_rng();
        let mut nonce = [0u8; AES256_NONCE_LENGTH];
        rng.fill_bytes(&mut nonce);

        let mut out = nonce.to_vec();
        let mut cipher_text = cipher.encrypt(&msg, &nonce, aad)?;
        out.append(&mut cipher_text);
        Ok(out)
    }

    pub fn decrypt_msg(
        &self,
        recipient_handle: Sha256Hash,
        msg: Vec<u8>,
    ) -> Result<Vec<u8>, X3dhError> {
        let nonce = array_ref![msg, 0, AES256_NONCE_LENGTH];
        let cipher_text = &msg[AES256_NONCE_LENGTH..];
        let cipher = self
            .decryption_keys
            .get(&recipient_handle)
            .ok_or_else(|| X3dhError::from("could not find decryption key"))?;
        let aad = self
            .associated_data
            .get(&recipient_handle)
            .ok_or_else(|| X3dhError::from("could not find associated data"))?;
        let out = cipher.decrypt(cipher_text, nonce, aad)?;
        Ok(out)
    }

    fn new_one_time_key(&mut self) -> PublicKey {
        let private_key = PrivateKey::new();
        let public_key = PublicKey::from(&private_key);
        self.one_time_keys.insert(public_key.hash(), private_key);
        public_key
    }
}

impl Default for KeyVault {
    fn default() -> Self {
        KeyVault::new()
    }
}

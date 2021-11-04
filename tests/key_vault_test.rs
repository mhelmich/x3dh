extern crate x3dh;
use std::convert::TryFrom;
use x3dh::key_vault::KeyVault;
use x3dh::types::{InitialMessage, PrekeyBundle};

#[test]
fn test_basic() {
    let mut bob = KeyVault::new();
    let mut alice = KeyVault::new();
    // Bob cerates a prekey bundle.
    let bundle = bob.new_prekey_bundle();
    // Alice "downloads" a "prekey bundle" and processes it subsequently.
    let (bob_handle, initial_message) = alice.process_prekey_bundle(bundle).unwrap();
    // Bob receives "initial message" from Alice.
    let alice_handle = bob.process_initial_message(initial_message).unwrap();
    let msg = String::from("Hello Bob!");
    // Alice sends Bob a message by encrypting it.
    let cipher_text = alice
        .encrypt_msg(bob_handle, msg.as_bytes().to_vec())
        .unwrap();
    // Bob receives the message and decrypts it.
    let clear_text = bob.decrypt_msg(alice_handle, cipher_text).unwrap();
    // Tada!
    assert_eq!(msg.as_bytes().to_vec(), clear_text);
}

#[test]
fn test_serde() {
    let mut bob = KeyVault::new();
    let mut alice = KeyVault::new();

    let bundle1 = bob.new_prekey_bundle();
    let text1 = bundle1.to_base64();
    let bundle2 = PrekeyBundle::try_from(text1.clone()).unwrap();
    let text2 = bundle2.to_base64();
    assert_eq!(text1, text2);

    let (_, msg1) = alice.process_prekey_bundle(bundle1).unwrap();
    let text3 = msg1.to_base64();
    let msg2 = InitialMessage::try_from(text3.clone()).unwrap();
    let text4 = msg2.to_base64();
    assert_eq!(text3, text4);
}

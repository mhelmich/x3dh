extern crate x3dh;
use x3dh::key_vault::KeyVault;

#[test]
fn test_basic() {
    let mut bob = KeyVault::new();
    let mut alice = KeyVault::new();
    // Bob cerates a prekey bundle.
    let bundle = bob.new_prekey_bundle();
    bundle.to_base64();
    // Alice "downloads" a "prekey bundle" and processes it subsequently.
    let (bob_handle, initial_message) = alice.process_prekey_bundle(bundle).unwrap();
    initial_message.to_base64();
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

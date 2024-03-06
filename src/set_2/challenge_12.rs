//! Simple ECB Decryption?

use aes::{
    cipher::{generic_array::GenericArray, KeyInit},
    Aes128,
};

use crate::{
    set_1::{aes_128_ecb_encrypt, aes_128_ecb_encrypt_in_place, base64_to_bytes},
    set_2::{challenge_11::random_aes_key, detect_encryption_mode, BlockMode},
};

use super::{challenge_9::pkcs_7_in_place, pkcs_7};

/// Build an ecb encryptor function that will use the same key every time.
///
/// Every new call to const_ecb_encryptor will produce a new function the encypts under a different key
fn build_ecb_encryptor() -> impl for<'a> Fn(&'a [u8]) -> Vec<u8> {
    let key = random_aes_key();
    let hidden_message = base64_to_bytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");

    let exact_key = GenericArray::from(key);
    let cipher = Aes128::new(&exact_key);

    move |prefix| {
        let mut prefixed_hidden_message = prefix.to_vec();
        prefixed_hidden_message.extend_from_slice(&hidden_message);

        pkcs_7_in_place(&mut prefixed_hidden_message, 16);
        aes_128_ecb_encrypt_in_place(&mut prefixed_hidden_message, &cipher).unwrap();
        prefixed_hidden_message
    }
}

pub fn find_hidden_message_simple(a: usize) -> String {
    // find block size
    let encrypt = build_ecb_encryptor();
    let mut stim = Vec::with_capacity(a);
    let padded_hidden_message_length = encrypt(&stim).len();

    while encrypt(&stim).len() == padded_hidden_message_length {
        stim.push(0);
    }
    let block_size = encrypt(&stim).len() - padded_hidden_message_length;

    let hidden_message_length = padded_hidden_message_length - stim.len();
    // println!("hidden_message_length: {}", hidden_message_length);

    // println!("block_size: {block_size}");
    debug_assert!(block_size == 16);

    let mode = detect_encryption_mode(&encrypt);
    debug_assert!(mode == BlockMode::ECB);
    // println!("mode: {mode:?}");

    // println!("hidden_message_length: {padded_hidden_message_length:?}");

    let mut stimulus = (0..(padded_hidden_message_length + hidden_message_length))
        .into_iter()
        .map(|_| 0u8)
        .collect::<Vec<u8>>();

    for pos in 1..=hidden_message_length {
        let target = &encrypt(&stimulus[pos..padded_hidden_message_length])
            [(padded_hidden_message_length - block_size)..padded_hidden_message_length];

        // Change last value until it matches the target block
        let target_byte = pos + padded_hidden_message_length - 1;
        for v in 0..=255 {
            *stimulus.get_mut(target_byte).unwrap() = v;

            let slice_start = pos + padded_hidden_message_length - block_size;
            let test_slice = &stimulus[slice_start..(slice_start + block_size)];
            let candidate = &encrypt(test_slice)[..block_size];

            if candidate == target {
                break;
            }
        }
    }

    String::from_utf8_lossy(&stimulus[padded_hidden_message_length..]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attack() {
        let expected_string = "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n";
        let msg = find_hidden_message_simple(8);
        assert_eq!(expected_string, &msg);
    }

    #[test]
    fn closure_has_constant_key() {
        let encryptor = build_ecb_encryptor();
        let pt = vec![0; 32];
        let cipher_text_1 = encryptor(&pt);
        let cipher_text_2 = encryptor(&pt);
        assert_eq!(cipher_text_1, cipher_text_2)
    }

    #[test]
    fn closure_builder_has_dynamic_key() {
        let pt = vec![0; 32];
        let cipher_text_1 = build_ecb_encryptor()(&pt);
        let cipher_text_2 = build_ecb_encryptor()(&pt);
        assert_ne!(cipher_text_1, cipher_text_2)
    }
}

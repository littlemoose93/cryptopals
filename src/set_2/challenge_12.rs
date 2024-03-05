//! Simple ECB Decryption?

use crate::{
    set_1::{aes_128_ecb_encrypt, base64_to_bytes},
    set_2::{challenge_11::random_aes_key, detect_encryption_mode, BlockMode},
};

use super::pkcs_7;

/// Build an ecb encryptor function that will use the same key every time.
///
/// Every new call to const_ecb_encryptor will produce a new function the encypts under a different key
fn build_ecb_encryptor() -> impl for<'a> Fn(&'a [u8]) -> Vec<u8> {
    let key = random_aes_key();
    move |prefix| {
        let hidden_message = base64_to_bytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
        let mut plain_text = prefix.to_vec();
        plain_text.extend_from_slice(&hidden_message);

        let block_sized_text = pkcs_7(&plain_text, 16);
        let cipher_text = aes_128_ecb_encrypt(&block_sized_text, &key).unwrap();
        cipher_text
    }
}

pub fn find_hidden_message() -> String {
    // find block size
    let encrypt = build_ecb_encryptor();
    let mut stim = Vec::new();
    let padded_hidden_message_length = encrypt(&stim).len();
    while encrypt(&stim).len() == padded_hidden_message_length {
        stim.push(0);
    }
    let block_size = encrypt(&stim).len() - padded_hidden_message_length;
    println!("stim: {}", stim.len());
    let hidden_message_length = padded_hidden_message_length - stim.len();
    println!("hidden_message_length: {}", hidden_message_length);

    println!("block_size: {block_size}");
    debug_assert!(block_size == 16);

    let mode = detect_encryption_mode(&encrypt);
    debug_assert!(mode == BlockMode::ECB);
    println!("mode: {mode:?}");

    println!("hidden_message_length: {padded_hidden_message_length:?}");

    let mut decrypted_string = Vec::new();
    let all_zeros = (0..padded_hidden_message_length)
        .into_iter()
        .map(|_| 0u8)
        .collect::<Vec<u8>>();

    for pos in 1..=hidden_message_length {
        let zero_stimulus = all_zeros[pos..].to_vec();
        // Checking the last vlock
        let target = encrypt(&zero_stimulus)
            [(padded_hidden_message_length - block_size)..padded_hidden_message_length]
            .to_vec();

        for v in 0..=255 {
            let mut sample = zero_stimulus.clone();
            // Add known string
            sample.extend_from_slice(&decrypted_string);
            sample.push(v);
            debug_assert!(sample.len() == padded_hidden_message_length);
            let candidate = encrypt(&sample)
                [(padded_hidden_message_length - block_size)..padded_hidden_message_length]
                .to_vec();
            if candidate == target {
                decrypted_string.push(v);
                break;
            }
        }
        debug_assert!(decrypted_string.len() == pos, "pos: {pos}");
    }
    println!("decrypted message length: {}", decrypted_string.len());

    String::from_utf8_lossy(&decrypted_string).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attack() {
        let msg = find_hidden_message();
        println!("{msg}");
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
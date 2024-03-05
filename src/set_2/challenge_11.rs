use std::ops::Range;

use rand::Rng;

use crate::{
    set_1::{aes_128_ecb_encrypt, is_aes_ecb},
    set_2::{aes_128_cbc_encrypt, pkcs_7},
};

fn random_aes_key() -> [u8; 16] {
    rand::random()
}

/// Encrypts the plain_text under a random key and algorithm (ECB or CBC)
pub fn encryption_oracle(plain_text: &[u8]) -> Vec<u8> {
    let mut padded_text = random_padding_bytes(5..11);
    padded_text.extend_from_slice(plain_text);
    padded_text.extend_from_slice(&random_padding_bytes(5..11));

    let key = random_aes_key();
    let use_ecb: bool = rand::random();
    let cippher_text = match use_ecb {
        true => {
            println!("ecb");
            let block_sized_text = pkcs_7(&padded_text, 16);
            aes_128_ecb_encrypt(&block_sized_text, &key).unwrap()
        }
        false => {
            let iv = random_aes_key();
            println!("cbc");
            aes_128_cbc_encrypt(&iv, &padded_text, key)
        }
    };
    cippher_text
}

#[derive(Debug)]
pub enum BlockMode {
    ECB,
    CBC,
}

// Detects the encrytion mode of a blackbox function
pub fn detect_encryption_mode<F>(black_box_encryptor: F) -> BlockMode
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let plain_text = vec![0; 64];
    let cipher_text = black_box_encryptor(&plain_text);
    if is_aes_ecb(&cipher_text) {
        BlockMode::ECB
    } else {
        BlockMode::CBC
    }
}

fn random_padding_bytes(range: Range<usize>) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let number_of_bytes = rng.gen_range(range);
    let mut padding = Vec::new();
    for _ in 0..number_of_bytes {
        padding.push(rand::random());
    }
    padding
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples() {
        for _ in 0..10 {
            let mode = detect_encryption_mode(encryption_oracle);
            println!("detect mode: {mode:?}\n");
        }
        assert!(false);
    }
}

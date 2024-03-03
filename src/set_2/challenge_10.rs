use crate::set_1::{aes_128_ecb_decryt, aes_128_ecb_encrypt, xor_exact};

pub fn aes_128_cbc_encrypt(iv: &[u8; 16], plain_text: &[u8], key: [u8; 16]) -> Vec<u8> {
    assert!(iv.len() == 16);
    assert!(plain_text.len() % 16 == 0);
    let mut output = Vec::new();

    let mut cipher_text = iv.to_vec();
    for (block_number, chunk) in plain_text.chunks(16).enumerate() {
        // println!("({block_number}) key: {key:x?}");
        // println!("({block_number}) previous cipher_text: {cipher_text:x?}");
        // println!("({block_number}) chunk: {chunk:x?}");
        let input = xor_exact(&cipher_text, chunk).unwrap();
        // println!("({block_number}) input: {input:x?}");

        cipher_text = aes_128_ecb_encrypt(&input, &key).unwrap();
        // println!("({block_number}) cipher_text: {cipher_text:x?}");

        output.extend_from_slice(&cipher_text);
    }

    output
}

pub fn aes_128_cbc_decrypt(iv: &[u8; 16], ciphertext: &[u8], key: [u8; 16]) -> Vec<u8> {
    assert!(iv.len() == 16);
    assert!(ciphertext.len() % 16 == 0);

    let mut output = Vec::new();
    let mut previous_cipher_text = iv.to_vec();

    for block in ciphertext.chunks(16) {
        let almost_pt = aes_128_ecb_decryt(block, &key).unwrap();
        let plain_text = xor_exact(&almost_pt, &previous_cipher_text).unwrap();
        output.extend_from_slice(&plain_text);
        previous_cipher_text = block.to_vec()
    }

    output
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use crate::set_1::base64_to_bytes;

    use super::*;

    #[test]
    fn challenge_sample() {
        let file_path = "src/set_2/challenge_10/aes-128-cbc.txt";

        let mut ciphertext_b64 = String::new();
        std::fs::File::open(file_path)
            .unwrap()
            .read_to_string(&mut ciphertext_b64)
            .unwrap();
        ciphertext_b64.retain(|c| !c.is_whitespace());
        let cipher_text = base64_to_bytes(&ciphertext_b64);

        let key: [u8; 16] = "YELLOW SUBMARINE".as_bytes().try_into().unwrap();
        let iv = [0; 16];

        let plaintext = aes_128_cbc_decrypt(&iv, &cipher_text, key);
        println!("{}", String::from_utf8_lossy(&plaintext));
        assert!(false);
    }

    #[test]
    fn encrypt_and_decrypt() {
        let plain_text = [0; 48].to_vec();
        let key = [1; 16];
        let iv = [2; 16];

        let cipher_text = aes_128_cbc_encrypt(&iv, &plain_text, key.clone());
        assert_ne!(cipher_text, plain_text);

        let decypted_plain_text = aes_128_cbc_decrypt(&iv, &cipher_text, key.clone());
        assert_eq!(plain_text, decypted_plain_text);
    }

    mod aes_128_cbc_encrypt {
        use crate::set_1::hex_to_bytes;

        use super::*;

        #[test]
        fn known_vectors_16_bytes() {
            let key: [u8; 16] = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c")
                .unwrap()
                .try_into()
                .unwrap();
            let iv: [u8; 16] = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
                .unwrap()
                .try_into()
                .unwrap();

            let plain_text = hex_to_bytes("6bc1bee22e409f96e93d7e117393172a").unwrap();
            let expected_cipher_text = hex_to_bytes("7649abac8119b246cee98e9b12e9197d").unwrap();
            let cipher_text = aes_128_cbc_encrypt(&iv, &plain_text, key);

            assert_eq!(expected_cipher_text, cipher_text);
        }

        #[test]
        fn known_vectors_32_bytes() {
            let key: [u8; 16] = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c")
                .unwrap()
                .try_into()
                .unwrap();
            let iv: [u8; 16] = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
                .unwrap()
                .try_into()
                .unwrap();

            let plain_text =
                hex_to_bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
                    .unwrap();
            let expected_cipher_text =
                hex_to_bytes("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2")
                    .unwrap();
            let cipher_text = aes_128_cbc_encrypt(&iv, &plain_text, key);

            assert_eq!(expected_cipher_text, cipher_text);
        }
        #[test]
        fn known_vectors_48_bytes() {
            let key: [u8; 16] = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c")
                .unwrap()
                .try_into()
                .unwrap();
            let iv: [u8; 16] = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
                .unwrap()
                .try_into()
                .unwrap();

            let plain_text = hex_to_bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52ef").unwrap();
            let expected_cipher_text = hex_to_bytes("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e22229516").unwrap();
            let cipher_text = aes_128_cbc_encrypt(&iv, &plain_text, key);

            assert_eq!(expected_cipher_text, cipher_text);
        }
    }
}
